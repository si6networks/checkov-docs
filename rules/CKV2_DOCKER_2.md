# CKV2_DOCKER_2: Ensure that certificate validation isn't disabled with curl
## Severity
**HIGH** (score: 7.5/10)

Disabling curl's TLS certificate validation during a Dockerfile build exposes package/script downloads to man-in-the-middle tampering, letting a network-position attacker inject malicious content that gets baked permanently into image layers built as root.

## Summary
This check fails a Dockerfile if any `RUN` instruction invokes `curl` with the `--insecure` (or short `-k`) flag, which disables TLS certificate validation for the request.

## Applicability
Applies to `Dockerfile` builds. It is implemented as a Checkov graph-based check (a JSON policy) that scans `RUN` instructions (`resource_types: ["RUN"]`); it is not tied to any cloud provider.

## Why it matters
`curl --insecure`/`-k` disables verification of the remote server's TLS certificate chain and hostname. Any build step that downloads dependencies, base layers, keys, or installer scripts over HTTPS with this flag is fully exposed to man-in-the-middle (MITM) attacks: a network-position attacker (malicious proxy, compromised DNS, hostile Wi-Fi, poisoned build cache mirror) can serve a forged response — for example a trojanized `install.sh` or a tampered package — and curl will accept it silently. Because Dockerfile `RUN` steps often execute with root privileges during the build and their output gets baked permanently into image layers, a single insecure download can inject malware or backdoors into every container built from that image, with no runtime indicator that anything is wrong. This is especially dangerous in CI pipelines where build agents commonly sit behind corporate TLS-intercepting proxies, which is often *why* developers add `--insecure` in the first place — masking a configuration problem (missing trusted CA bundle) with a much larger security hole.

## How Checkov evaluates this
The check is a graph JSON policy with a single `attribute` condition on `RUN` instructions: it takes the instruction's `value` (the shell command string) and requires it to **not** match the regex
```
.*(curl[^\|&;]*\s+((--insecure)|(-[^-\s]*k))).*
```
This looks for the token `curl` followed (within the same shell command, i.e. not separated by `|`, `&`, or `;`) by whitespace and then either the literal `--insecure` flag or a short-option cluster ending in `k` (e.g. `-k`, `-sk`, `-fsSLk`). If any `RUN` line matches that pattern, the check **FAILs**; if no `RUN` instruction contains an insecure curl invocation, it **PASSes**.

## Non-compliant example
```dockerfile
FROM debian:12-slim
RUN curl -sSk https://example.com/install.sh -o /tmp/install.sh && \
    sh /tmp/install.sh
```

## Remediated example
```dockerfile
FROM debian:12-slim
# Removed -k / --insecure; ensure the base image has an up-to-date CA bundle instead
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    curl -sSL https://example.com/install.sh -o /tmp/install.sh && \
    sh /tmp/install.sh
```

## Remediation steps
1. Remove `--insecure`/`-k` from every `curl` invocation in `RUN` instructions.
2. If curl fails with a certificate error, diagnose the real cause instead of bypassing validation:
   - Install/update the `ca-certificates` package in the build stage before the curl call.
   - If behind a corporate TLS-intercepting proxy, add the proxy's root CA to the image's trust store (e.g. copy the cert into `/usr/local/share/ca-certificates/` and run `update-ca-certificates`) rather than disabling verification.
3. Pin downloads to a known-good checksum (e.g. verify a SHA256 sum after download) as defense in depth, in addition to TLS validation.
4. Re-run `checkov -f Dockerfile` (or your CI scan) to confirm the finding clears.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunUnsafeCurl.json
