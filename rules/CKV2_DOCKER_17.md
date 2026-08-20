# CKV2_DOCKER_17: Ensure that 'chpasswd' is not used to set or remove passwords

## Severity
**MEDIUM** (score: 5.0/10)

Using chpasswd to set account passwords directly in a Dockerfile RUN instruction typically hardcodes credential material into image layers, where it remains recoverable by anyone with access to the image history.

## Summary
This check verifies that no `RUN` instruction in a Dockerfile invokes the `chpasswd` utility to set or remove user passwords.

## Applicability
- **Dockerfile**: any `RUN` instruction.

This is a graph-based check that pattern-matches the literal text of `RUN` instruction values (start, contains, and end anchors).

## Why it matters
Setting passwords via `chpasswd` inside a Dockerfile bakes credential material (or credential-setting logic) directly into image layers. Even if the password is later "removed" or changed, Docker image layers are immutable and cumulative — any password set in an earlier layer remains recoverable from the image history/layer cache by anyone who can pull or inspect the image (`docker history`, extracting layer tarballs), regardless of what a later layer does. This is a common way secrets leak into container registries: a plaintext or weakly-hashed password embedded in a `RUN chpasswd` command becomes part of the distributable artifact, potentially exposing default/service account credentials to anyone with pull access to the image, including in public registries if the image is ever pushed there by mistake.

## How Checkov evaluates this
The check is a JSON graph query with three literal string conditions combined with `and` (all three must hold for the instruction to pass):

- FAIL: the `RUN` command starts with `"chpasswd "`.
- FAIL: the `RUN` command contains `" chpasswd "` (used mid-chain, e.g. after `&&`).
- FAIL: the `RUN` command ends with `" chpasswd"`.
- PASS: none of the three patterns match — i.e., `chpasswd` does not appear as a standalone command anywhere in the `RUN` instruction.

## Non-compliant example
```dockerfile
FROM ubuntu:22.04

RUN echo "appuser:S3cretPass123" | chpasswd
```

## Remediated example
```dockerfile
FROM ubuntu:22.04

# Removed chpasswd/hardcoded password. Password auth is disabled for this
# service account; access is via SSH key or handled by the orchestrator's
# secret-injection mechanism at runtime instead.
RUN useradd --create-home --shell /bin/bash appuser && \
    passwd --lock appuser
```

## Remediation steps
1. Remove any `RUN` instruction that pipes credentials into `chpasswd` (or calls it directly).
2. If a service account inside the container needs to exist but should never be logged into interactively, lock the account (`passwd --lock` / `usermod -L`) instead of setting a real password.
3. If a password truly must be provisioned, inject it at container **runtime** via an orchestrator secret (Kubernetes Secret, Docker secret, environment variable sourced from a secrets manager) rather than baking it into the image at build time.
4. If this pattern exists for local development convenience, move it to a separate, clearly-labeled dev-only Dockerfile/compose override that is never pushed to a shared registry, and still avoid hardcoding real/production-adjacent credentials.
5. If a password was already baked into a previously-built and pushed image, treat that credential as compromised — rotate it — since removing the `chpasswd` line in a new build does not remove the exposure from previously distributed image layers.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunChpasswd.json)
