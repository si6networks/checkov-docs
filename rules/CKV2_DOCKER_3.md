# CKV2_DOCKER_3: Ensure that certificate validation isn't disabled with wget
## Severity
**HIGH** (score: 7.5/10)

wget's --no-check-certificate disables TLS validation for build-time downloads, allowing a MITM attacker to substitute a forged artifact that is silently trusted and permanently embedded in the resulting image.

## Summary
This check fails a Dockerfile if any `RUN` instruction invokes `wget` with `--no-check-certificate`, which disables TLS certificate validation for the download.

## Applicability
Applies to `Dockerfile` builds. Implemented as a Checkov graph-based JSON policy scanning `RUN` instructions (`resource_types: ["RUN"]`).

## Why it matters
`wget --no-check-certificate` skips verification of the server's TLS certificate chain and hostname, exactly like curl's `--insecure`. Any artifact, script, or package fetched this way during image build can be silently swapped by a network-position attacker (rogue proxy, ARP/DNS spoofing, compromised CDN edge, hostile network) without any error being raised. Because Docker build steps typically run as root and their results are committed permanently into image layers — and later distributed to every container instance and every downstream consumer of that image — a single tampered `wget` download at build time can plant a persistent backdoor across an entire fleet, and there's no way to detect it after the fact from the running container alone.

## How Checkov evaluates this
Single `attribute` condition on `RUN` instructions: the instruction's `value` must **not** match
```
.*(wget[^\|&;]*\s+--no-check-certificate).*
```
i.e. the string `wget` followed (within the same shell command segment) by the literal flag `--no-check-certificate`. A match on any `RUN` line **FAILs** the check; absence of the flag **PASSes**.

## Non-compliant example
```dockerfile
FROM alpine:3.19
RUN wget --no-check-certificate https://example.com/app.tar.gz -O /tmp/app.tar.gz && \
    tar -xzf /tmp/app.tar.gz -C /opt
```

## Remediated example
```dockerfile
FROM alpine:3.19
RUN apk add --no-cache ca-certificates && \
    wget https://example.com/app.tar.gz -O /tmp/app.tar.gz && \
    tar -xzf /tmp/app.tar.gz -C /opt
```

## Remediation steps
1. Remove `--no-check-certificate` from all `wget` calls in `RUN` instructions.
2. Ensure the build stage has an up-to-date CA trust bundle installed (`ca-certificates` on Debian/Ubuntu/Alpine) before performing HTTPS downloads.
3. If a corporate proxy performs TLS interception, install that CA into the image's trust store instead of disabling validation.
4. Add a checksum/signature verification step after download as defense in depth.
5. Re-scan with Checkov to confirm the finding is resolved.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunUnsafeWget.json
