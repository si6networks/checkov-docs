# CKV_DOCKER_6: Ensure that LABEL maintainer is used instead of MAINTAINER (deprecated)

## Severity
**LOW** (score: 2.0/10)

MAINTAINER vs. LABEL maintainer is a deprecated-syntax/metadata convention with no exploitable security impact.

## Summary
This check always fails when a Dockerfile uses the deprecated `MAINTAINER` instruction, since Docker recommends using a `LABEL maintainer="..."` instead.

## Applicability
**Checkov framework(s):** `dockerfile`

Dockerfiles — specifically the `MAINTAINER` instruction.

## Why it matters
`MAINTAINER` was deprecated by Docker years ago in favor of the generic `LABEL` mechanism. This is primarily a maintainability/convention issue rather than a direct exploit vector, but it matters for security hygiene in a supporting sense: standardizing on `LABEL` (e.g., `LABEL maintainer=`, `LABEL org.opencontainers.image.source=`, `LABEL org.opencontainers.image.vendor=`) keeps image metadata consistent and machine-readable across your fleet, which downstream tooling (SBOM generators, image scanners, provenance/attestation tools, incident-response scripts that need to identify "who owns this image") often depends on. Deprecated instructions are also a signal of an unmaintained or copy-pasted Dockerfile, which frequently correlates with other unaddressed hygiene issues (stale base images, missing `USER`/`HEALTHCHECK`, etc.).

## How Checkov evaluates this
The check (`MaintainerExists`) is registered against the `MAINTAINER` instruction. Its `scan_resource_conf` unconditionally returns `CheckResult.FAILED` for the given configuration — meaning any presence of a `MAINTAINER` instruction in the Dockerfile causes this check to fail; there is no passing branch, because the check is only ever invoked when at least one `MAINTAINER` instruction exists in the file.

## Non-compliant example
```dockerfile
FROM python:3.12-slim
MAINTAINER platform-team@example.com

WORKDIR /app
COPY . .
CMD ["python", "app.py"]
```

## Remediated example
```dockerfile
FROM python:3.12-slim
LABEL maintainer="platform-team@example.com"

WORKDIR /app
COPY . .
CMD ["python", "app.py"]
```

## Remediation steps
1. Replace `MAINTAINER <value>` with `LABEL maintainer="<value>"`.
2. Consider adopting the OCI standard image labels (`org.opencontainers.image.authors`, `org.opencontainers.image.source`, `org.opencontainers.image.vendor`, etc.) alongside or instead of a bare `maintainer` label, since these are recognized by a broader set of tooling.
3. Search the rest of your Dockerfiles/base images for other lingering `MAINTAINER` usage — it's often copy-pasted across many services.
4. Re-run `checkov -f Dockerfile` to confirm the finding clears.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/MaintainerExists.py
- Docker MAINTAINER deprecation note (Dockerfile reference): https://docs.docker.com/reference/dockerfile/#maintainer-deprecated
