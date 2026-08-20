# CKV2_DOCKER_5: Ensure that certificate validation isn't disabled with the PYTHONHTTPSVERIFY environment variable
## Severity
**HIGH** (score: 7.5/10)

Setting PYTHONHTTPSVERIFY=0 via ARG/ENV/RUN disables certificate validation for all Python HTTPS calls, and because it is an image-level environment variable the exposure typically persists into the running container at runtime, not just during the build.

## Summary
This check fails a Dockerfile if it sets the `PYTHONHTTPSVERIFY` environment variable to `0` (via `ARG`, `ENV`, or an inline assignment in a `RUN` command), which globally disables Python's `ssl`/`urllib`/`pip` certificate verification for the whole build (or runtime) environment.

## Applicability
Applies to `Dockerfile` builds. Implemented as a Checkov graph-based JSON policy that checks `ARG`, `ENV`, and `RUN` instructions.

## Why it matters
`PYTHONHTTPSVERIFY=0` is a blunt, environment-wide kill switch for TLS certificate verification in Python's standard library HTTPS handling (it was historically used to work around Python 2.7.9's stricter default `ssl` behavior). Setting it disables verification for *every* HTTPS connection made by Python code in that environment — not just one command — including `pip install`, application HTTP clients, and any script that shells out to Python. Because `ENV`/`ARG` values persist for the rest of the image build (and `ENV` persists into the running container unless explicitly unset), this is far broader and more dangerous than a single insecure `curl` call: it silently reintroduces MITM exposure to every subsequent Python-based network operation in the image, including ones added later by other maintainers who have no idea the protection was disabled.

## How Checkov evaluates this
This is an `or` of two `attribute` conditions, so the check FAILs if *either* is true:
1. Any `ARG` or `ENV` instruction's `value` matches `(.*\s+)?(PYTHONHTTPSVERIFY(=|\s+)((0)|('0')|("0")))`.*` — i.e. `PYTHONHTTPSVERIFY` set to `0` (unquoted, single-quoted, or double-quoted) via `=` or whitespace assignment.
2. Any `RUN` instruction's `value` matches `(.*[\s;&|]+)?(PYTHONHTTPSVERIFY=((0)|('0')|("0"))) .*` — i.e. an inline `PYTHONHTTPSVERIFY=0` prefix before a shell command within a `RUN` line.

If neither pattern is found, the check PASSes.

## Non-compliant example
```dockerfile
FROM python:3.12-slim
ENV PYTHONHTTPSVERIFY=0
RUN pip install requests
```

## Remediated example
```dockerfile
FROM python:3.12-slim
# PYTHONHTTPSVERIFY not set -> Python's default strict certificate verification applies
RUN pip install requests
```

## Remediation steps
1. Remove any `ENV PYTHONHTTPSVERIFY=0`, `ARG PYTHONHTTPSVERIFY=0`, or inline `PYTHONHTTPSVERIFY=0 <command>` usage from the Dockerfile.
2. If verification failures prompted this workaround, fix the underlying trust-store problem: install/update `ca-certificates`, or add your organization's internal CA to the container's trust store.
3. Audit any base images you inherit from (`FROM`) for this variable being set upstream, since `ENV` values propagate to child images.
4. Re-scan with Checkov after removal.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/EnvPythonHttpsVerify.json
