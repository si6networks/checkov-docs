# CKV_DOCKER_4: Ensure that COPY is used instead of ADD in Dockerfiles

## Severity
**LOW** (score: 2.0/10)

ADD's implicit remote-URL fetching and auto-extraction of archives (tar, zip) can introduce unreviewed remote content into the image and is a known vector for path-traversal/zip-slip during extraction, risks COPY does not carry.

## Summary
This check fails a Dockerfile whenever it contains an `ADD` instruction, requiring the use of the more predictable `COPY` instruction instead.

## Applicability
Dockerfiles — specifically the `ADD` instruction.

## Why it matters
`ADD` has "magic" behaviors that `COPY` does not: it can fetch content from a remote URL directly into the image, and it automatically extracts recognized local archive files (tar, gzip, etc.) into the destination directory. Both behaviors are security-relevant: (1) `ADD <url> <dest>` fetches remote content at build time over whatever the Dockerfile author configured — often without TLS-pinning, integrity verification, or a way for a reviewer to know at a glance that the build pulls untrusted network content, exposing the build to man-in-the-middle tampering, dependency confusion, or fetching from an expired/compromised domain; (2) automatic archive extraction is a well-known vector for "zip-slip"/tar path-traversal vulnerabilities, where a malicious or corrupted archive can write files outside the intended destination directory during the extraction `ADD` performs implicitly. `COPY` does neither — it is a plain, predictable file copy from the build context, which is why Docker's own official best practices recommend `COPY` unless you specifically need one of `ADD`'s extra behaviors (and even then, recommend doing the extraction/fetch explicitly and verifiably instead).

## How Checkov evaluates this
The check (`AddExists`) iterates the parsed instructions and looks for any instruction whose `instruction` field equals `"ADD"`. If found, the check FAILS immediately. If no `ADD` instruction is present anywhere in the Dockerfile, it PASSES.

## Non-compliant example
```dockerfile
FROM alpine:3.19

ADD https://example.com/app-release.tar.gz /tmp/
ADD app-config.tar.gz /etc/app/

CMD ["/etc/app/start.sh"]
```

## Remediated example
```dockerfile
FROM alpine:3.19

RUN apk add --no-cache curl \
    && curl -fsSL https://example.com/app-release.tar.gz -o /tmp/app-release.tar.gz \
    && sha256sum /tmp/app-release.tar.gz | grep -q "<expected-sha256>" \
    && tar -xzf /tmp/app-release.tar.gz -C /tmp \
    && rm /tmp/app-release.tar.gz

COPY app-config.tar.gz /etc/app/app-config.tar.gz
RUN tar -xzf /etc/app/app-config.tar.gz -C /etc/app && rm /etc/app/app-config.tar.gz

CMD ["/etc/app/start.sh"]
```

## Remediation steps
1. Replace every `ADD <local-file> <dest>` with `COPY <local-file> <dest>` — this is a drop-in replacement for plain local file copies.
2. For `ADD <url> <dest>` (remote fetch), replace it with an explicit `RUN curl`/`wget` step that downloads over HTTPS and verifies the artifact's checksum/signature before use.
3. For local archive files that relied on `ADD`'s auto-extraction, use `COPY` to place the archive in the image and add an explicit `RUN tar -xzf ...` step, so the extraction behavior is visible and auditable in the Dockerfile rather than implicit.
4. Delete temporary downloaded/extracted archives in the same `RUN` layer to avoid bloating image size with intermediate files.
5. Re-run the scan against the listed example Dockerfiles to confirm each now passes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/AddExists.py
- Docker best practices (ADD vs COPY): https://docs.docker.com/build/building/best-practices/#add-or-copy
