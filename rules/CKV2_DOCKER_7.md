# CKV2_DOCKER_7: Ensure that packages with untrusted or missing signatures are not used by apk via the '--allow-untrusted' option
## Severity
**MEDIUM** (score: 5.0/10)

apk's --allow-untrusted flag skips package signature verification on Alpine, so a compromised or spoofed package mirror can deliver tampered, malicious packages that install with full build-time privileges.

## Summary
This check fails a Dockerfile if any `RUN` instruction invokes Alpine's `apk` package manager with `--allow-untrusted`, which installs packages even when their signature cannot be verified.

## Applicability
**Checkov framework(s):** `dockerfile`

Applies to `Dockerfile` builds (typically Alpine-based images). Implemented as a Checkov graph-based JSON policy scanning `RUN` instructions (`resource_types: ["RUN"]`).

## Why it matters
Alpine package signing exists so that `apk` can cryptographically verify that a `.apk` package actually came from a trusted repository and hasn't been tampered with in transit or at rest (e.g. on a compromised mirror). `--allow-untrusted` disables that check entirely, meaning `apk` will install any package regardless of whether its signature is valid, missing, or forged. Combined with the fact that `apk add` typically runs as root during image build and installs binaries/libraries that end up in every derived container, an attacker who can intercept the connection to the package mirror (MITM) or compromise a mirror itself can supply a malicious package that gets silently installed and trusted — a classic software supply-chain compromise vector.

## How Checkov evaluates this
Single `attribute` condition on `RUN` instructions: the `value` must **not** match
```
.*(apk[^\|&;]*\s+--allow-untrusted).*
```
i.e. `apk` followed (within the same shell segment) by `--allow-untrusted`. A match **FAILs**; absence **PASSes**.

## Non-compliant example
```dockerfile
FROM alpine:3.19
RUN apk add --allow-untrusted --no-cache mypackage
```

## Remediated example
```dockerfile
FROM alpine:3.19
RUN apk add --no-cache mypackage
```

## Remediation steps
1. Remove `--allow-untrusted` from every `apk` invocation.
2. If the failure is due to a custom/internal repository lacking a trusted signing key, add that repository's public key to `/etc/apk/keys/` instead of bypassing verification, and reference the repo via `--repository` with the key properly registered.
3. Prefer official Alpine repositories or a properly signed internal mirror.
4. Re-scan with Checkov to confirm the flag is gone.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunApkAllowUntrusted.json
