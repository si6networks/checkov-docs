# CKV_DOCKER_8: Ensure the last USER is not root

## Severity
**LOW** (score: 2.0/10)

Leaving the container running as root significantly increases the blast radius of any application compromise or container-escape, potentially granting an attacker root-level privileges on the underlying host.

## Summary
This check ensures that the final `USER` instruction in a Dockerfile does not set the container's runtime user to `root`, so containers built from the image do not run as the root user by default.

## Applicability
- **IaC framework**: Dockerfile
- **Instruction inspected**: `USER`
- Only the *last* `USER` instruction in the Dockerfile is evaluated (a Dockerfile may switch users multiple times, e.g., to `root` for installing packages and back to a non-root user before `CMD`/`ENTRYPOINT` — only the final, effective one matters for runtime).

## Why it matters
Containers, by default, run as `root` (UID 0) unless a `USER` instruction changes that. Running application processes as root inside a container is dangerous because:

- **Container escape amplification**: If an attacker exploits a vulnerability in the application or a container runtime bug (e.g., certain kernel/cgroup escapes), running as root inside the container makes it far more likely that the same exploit yields root on the host, or at minimum root within the container's namespace, from which further privilege escalation and lateral movement is easier.
- **Filesystem and capability exposure**: A root process inside the container retains a broad set of Linux capabilities by default (unless explicitly dropped), and can read/write any file the container's mount namespace exposes, including mounted secrets, host paths, or Docker socket bind-mounts if misconfigured elsewhere.
- **Defense-in-depth failure**: Kubernetes `PodSecurityPolicy`/`PodSecurityStandards`, seccomp profiles, and `runAsNonRoot` admission controls all assume (or actively enforce) that images don't require root; an image hardcoded to run as root undermines these controls or forces exceptions to be carved out for it.
- **Blast radius of image compromise**: If the image itself is compromised (e.g., a malicious dependency), a root-running process has unrestricted ability to modify the running container, install additional tooling, or pivot within the container network.

## How Checkov evaluates this
The check (`RootUser`) looks only at the **last** `USER` instruction in the Dockerfile:
- **FAILS** if that last `USER` instruction's value is exactly `"root"`.
- **PASSES** for any other user value (a named non-root user or a non-zero, non-"root" UID string).

Note: the check is a literal string match on `"root"` — it does not resolve numeric UID `0` to "root", so `USER 0` would not be caught by this specific check even though it is functionally equivalent to root.

## Non-compliant example
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y myapp
USER root

CMD ["myapp"]
```

## Remediated example
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y myapp \
    && useradd --create-home --shell /bin/bash appuser
USER appuser

CMD ["myapp"]
```

## Remediation steps
1. Create a dedicated, unprivileged user and group in the Dockerfile (e.g., `RUN useradd -m appuser` or, for Alpine, `RUN adduser -D appuser`).
2. Ensure that user owns any directories/files the application needs to read or write (`RUN chown -R appuser:appuser /app`).
3. Place the final `USER appuser` instruction after all root-requiring setup steps (package installs, chown, binding to privileged ports below 1024 if applicable) and before `CMD`/`ENTRYPOINT`.
4. If the app must bind to a privileged port, prefer remapping to a high port and letting the orchestrator (Kubernetes Service, load balancer) do the port translation, rather than running as root.
5. In Kubernetes, pair this with a `securityContext.runAsNonRoot: true` and `runAsUser` on the Pod/container spec for defense in depth.
6. Re-scan with Checkov; avoid relying solely on numeric UID 0 as a workaround since it defeats the intent of this control even if it isn't literally caught by the string match.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/RootUser.py
- Docker docs on USER instruction: https://docs.docker.com/reference/dockerfile/#user
