# CKV2_DOCKER_9: Ensure that packages with untrusted or missing GPG signatures are not used by dnf, tdnf, or yum via the '--nogpgcheck' option
## Severity
**MEDIUM** (score: 5.0/10)

The --nogpgcheck flag on dnf/tdnf/yum disables RPM package signature verification, letting a compromised or spoofed repository serve tampered packages that are installed without any cryptographic integrity check.

## Summary
This check fails a Dockerfile if any `RUN` instruction invokes `yum`, `dnf`, or `tdnf` with the `--nogpgcheck` option, which skips GPG signature verification of installed RPM packages.

## Applicability
Applies to `Dockerfile` builds (RHEL/CentOS/Fedora/Photon OS-based images using yum, dnf, or tdnf). Implemented as a Checkov graph-based JSON policy scanning `RUN` instructions.

## Why it matters
RPM-based distributions sign package metadata and packages with GPG keys so the package manager can cryptographically confirm a package came from a trusted repository and hasn't been altered. `--nogpgcheck` disables that verification for the whole transaction, meaning any package — legitimate or maliciously substituted — will be installed without complaint. This is a classic supply-chain weak point: an attacker positioned to intercept the connection to the repository mirror (MITM), or one who has compromised a mirror or CDN cache, can serve a trojanized RPM that gets silently installed as root during the image build and persists in every derived container image. `--nogpgcheck` is often added reflexively to "fix" a GPG key import failure, which really should be resolved by installing the correct signing key instead.

## How Checkov evaluates this
Single `attribute` condition on `RUN` instructions: the `value` must **not** match
```
.*(((t?dnf)|(yum))[^\|&;]*\s+--nogpgcheck).*
```
i.e. `yum`, `dnf`, or `tdnf` followed (within the same shell command segment) by `--nogpgcheck`. A match **FAILs**; absence **PASSes**.

## Non-compliant example
```dockerfile
FROM rockylinux:9
RUN dnf install -y --nogpgcheck httpd
```

## Remediated example
```dockerfile
FROM rockylinux:9
RUN dnf install -y httpd
```

## Remediation steps
1. Remove `--nogpgcheck` from all `yum`/`dnf`/`tdnf` invocations.
2. If GPG verification is failing because a repository's signing key isn't imported, import the correct key explicitly (e.g. `rpm --import <key-url>` or configure `gpgkey=` in the repo's `.repo` file) instead of bypassing verification.
3. Confirm the repository is served over HTTPS and sourced from a trusted vendor/mirror.
4. Re-scan with Checkov to confirm the finding is resolved.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunYumNoGpgCheck.json
