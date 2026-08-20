# CKV2_DOCKER_8: Ensure that packages with untrusted or missing signatures are not used by apt-get via the '--allow-unauthenticated' option
## Severity
**MEDIUM** (score: 5.0/10)

apt-get's --allow-unauthenticated flag disables GPG signature checks on Debian/Ubuntu packages, allowing an attacker who controls or spoofs a repository/mirror to supply a malicious package that is installed and trusted without verification.

## Summary
This check fails a Dockerfile if any `RUN` instruction invokes Debian/Ubuntu's `apt-get` with `--allow-unauthenticated`, which permits installing packages that fail GPG signature verification.

## Applicability
Applies to `Dockerfile` builds (Debian/Ubuntu-based images). Implemented as a Checkov graph-based JSON policy scanning `RUN` instructions.

## Why it matters
Debian's APT repository model relies on GPG-signed `Release`/`Packages` metadata so that `apt-get` can prove a downloaded `.deb` package genuinely came from a trusted repository and was not modified. `--allow-unauthenticated` (and its alias `--allow-unauthenticated-repositories`) tells apt to proceed even when that signature check fails or is absent. This removes the integrity guarantee for every package installed in that command: a network attacker who can intercept the connection to the APT mirror, or a compromised/rogue mirror, can serve a tampered package and apt will install it without complaint. Since `apt-get install` in a Dockerfile typically runs as root and its results are baked permanently into image layers shared across every container instantiated from that image, this is a high-impact supply-chain exposure — and it's often introduced as a quick fix for an expired or misconfigured repository key, masking a real problem with a much bigger one.

## How Checkov evaluates this
Single `attribute` condition on `RUN` instructions: the `value` must **not** match
```
.*(apt-get[^\|&;]*\s+--allow-unauthenticated).*
```
i.e. `apt-get` followed (within the same shell command segment) by `--allow-unauthenticated`. A match **FAILs**; absence **PASSes**.

## Non-compliant example
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y --allow-unauthenticated curl
```

## Remediated example
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y curl
```

## Remediation steps
1. Remove `--allow-unauthenticated` from all `apt-get` commands.
2. If a custom/internal APT repository is failing signature checks, import its correct signing key via `apt-key` (deprecated) or, preferably, a keyring file referenced in the repo's `signed-by=` option in `sources.list.d`, rather than disabling verification.
3. Ensure the `ca-certificates` and `gnupg` packages are present and up to date so key/signature verification can succeed.
4. Re-scan with Checkov to confirm.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunAptGetAllowUnauthenticated.json
