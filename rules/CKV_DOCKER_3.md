# CKV_DOCKER_3: Ensure that a user for the container has been created

## Severity
**LOW** (score: 2.0/10)

Running a container without a declared non-root USER means the process runs as root by default, so a container-breakout or dependency-RCE vulnerability escalates directly to root-level access on the host's container runtime.

## Summary
This check requires that a Dockerfile contains a `USER` instruction, so the container's main process does not run as root by default.

## Applicability
**Checkov framework(s):** `dockerfile`

Dockerfiles — this check applies to the Dockerfile as a whole (`supported_instructions = ("*",)`) looking for a `USER` instruction anywhere in the file.

## Why it matters
If no `USER` instruction is present, a container runs as `root` (UID 0) by default. If an attacker achieves code execution inside such a container (via an application vulnerability, a malicious dependency, or a deserialization bug), running as root inside the container significantly raises the impact: it makes container-breakout techniques more viable (many kernel/container-runtime escape CVEs specifically require root inside the container to exploit), it allows the process to modify files owned by other UIDs within any mounted volumes, and it violates the principle of least privilege that container security best practices (CIS Docker Benchmark, NSA/CISA Kubernetes hardening guidance) explicitly call for. Running as a non-root user doesn't eliminate all risk, but it removes an entire class of privilege-escalation and lateral-movement techniques that assume root-in-container.

## How Checkov evaluates this
The check (`UserExists`), like `CKV_DOCKER_2`, receives the fully parsed Dockerfile as a mapping of instruction name to its occurrences. It iterates the instruction names present; if `"USER"` appears as a key anywhere in the file, the check PASSES. If no `USER` instruction exists, it FAILS. Note: the check only verifies that *some* `USER` instruction exists — it does not verify that the final effective user (after all `USER`/`FROM` stages) is actually non-root, so a `USER root` instruction would still satisfy this specific check.

## Non-compliant example
```dockerfile
FROM node:20-slim

WORKDIR /app
COPY . .
RUN npm ci --omit=dev

CMD ["node", "server.js"]
```

## Remediated example
```dockerfile
FROM node:20-slim

WORKDIR /app
COPY . .
RUN npm ci --omit=dev \
    && addgroup --system app && adduser --system --ingroup app app \
    && chown -R app:app /app

USER app
CMD ["node", "server.js"]
```

## Remediation steps
1. Create a dedicated non-root user/group in the image (via `RUN adduser`/`useradd`, or use a base image that already ships one, e.g. `node:20-slim` includes a `node` user).
2. Add a `USER <name>` instruction after all setup steps that require root (package installs, `chown`, binding to privileged ports below 1024), and before the `CMD`/`ENTRYPOINT`.
3. Ensure file ownership/permissions on `WORKDIR` and any data directories are set for that non-root user (`chown -R`) before switching, or the app will fail to read/write its own files.
4. If the app must bind a low port (e.g., 80/443), either remap to a higher port and put a reverse proxy/load balancer in front, or grant the specific Linux capability (`setcap`) instead of running as root.
5. Verify the container still functions correctly after the user switch — test locally with `docker run` before merging — since some base images assume root and may need extra `chown`/permission fixes.
6. Re-run the scan against the listed example Dockerfiles to confirm each now passes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/UserExists.py
- Docker USER reference: https://docs.docker.com/reference/dockerfile/#user
