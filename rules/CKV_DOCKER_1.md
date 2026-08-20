# CKV_DOCKER_1: Ensure port 22 is not exposed

## Severity
**MEDIUM** (score: 5.0/10)

Exposing port 22 from a container image invites SSH access into what should typically be a single-process container, increasing attack surface and often signaling an anti-pattern (running an SSH daemon in-container) that undermines container isolation.

## Summary
This check fails a Dockerfile if it contains an `EXPOSE` instruction listing port 22 (SSH), on the theory that containers generally should not run or expose an SSH daemon.

## Applicability
Dockerfiles — specifically the `EXPOSE` instruction.

## Why it matters
Containers are typically meant to run a single process/service and be managed via the container runtime/orchestrator (`docker exec`, `kubectl exec`), not accessed via SSH. Exposing port 22 usually indicates an SSH server is running inside the container, which: (1) significantly increases the container's attack surface (another network-facing daemon, another auth mechanism, another set of credentials/keys to manage and potentially leak), (2) works against the "immutable, single-purpose container" model that makes containers easy to patch (just rebuild/redeploy) — an SSH-accessible container invites ad hoc, undocumented changes made directly inside a running container, and (3) is a common vector attackers scan for and brute-force, especially if the image ships with default or weak credentials.

## How Checkov evaluates this
The check (`ExposePort22`) inspects every `EXPOSE` instruction in the Dockerfile. It splits the instruction's value on spaces and checks whether `"22"` or `"22/tcp"` appears as one of the tokens. If either token is present in any `EXPOSE` line, the check FAILS on that instruction. If port 22 is never exposed, it PASSES.

## Non-compliant example
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y openssh-server
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
```

## Remediated example
```dockerfile
FROM ubuntu:22.04

# Application listens on 8080 instead; no SSH server in the image
EXPOSE 8080
CMD ["/app/server"]
```

## Remediation steps
1. Remove the `EXPOSE 22` (or `EXPOSE 22/tcp`) instruction from the Dockerfile.
2. Remove any SSH server installation/startup (`openssh-server`, `sshd`) from the image unless there is a strong, documented operational requirement.
3. Use `docker exec`/`kubectl exec` (or your orchestrator's equivalent) for interactive debugging access instead of SSH into the container.
4. If remote access truly must be supported (e.g., certain legacy or vendor-mandated workloads), restrict it via network policy/security groups, enforce key-only auth, and document the exception rather than leaving it as an unreviewed default.
5. Re-run `checkov -f Dockerfile` (or your build pipeline's scan) to confirm the finding clears.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/ExposePort22.py
