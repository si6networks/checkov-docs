# CKV2_DOCKER_10: Ensure that packages with untrusted or missing signatures are not used by rpm via the '--nodigest', '--nosignature', '--noverify', or '--nofiledigest' options

## Severity
**HIGH** (score: 7.5/10)

Disabling rpm's digest/signature verification allows unsigned or tampered packages to be installed into the image, opening a supply-chain path for malicious or corrupted binaries to land in production containers.

## Summary
This check verifies that `rpm` invocations in a Dockerfile do not disable package integrity/signature verification via the `--nodigest`, `--nosignature`, `--noverify`, or `--nofiledigest` flags.

## Applicability
**Checkov framework(s):** `dockerfile`

- **Dockerfile**: any `RUN` instruction.

This is a graph-based check using regex matching against the `RUN` instruction's command text.

## Why it matters
RPM package signatures and digests exist to guarantee that a package was produced by a trusted vendor/repository and has not been tampered with in transit or on a compromised mirror. Disabling these checks (`--nosignature`, `--noverify`) means the build will happily install a package even if its GPG signature is missing, invalid, or does not match a trusted key — and disabling digest checks (`--nodigest`, `--nofiledigest`) means corrupted or maliciously modified file content within the package will not be detected either. This turns the Dockerfile's package installation step into a potential supply-chain injection point: a compromised mirror, a man-in-the-middle on an insecure repo URL, or a tampered local RPM file could all be installed into the image silently, embedding malicious code directly into container images that get deployed downstream.

## How Checkov evaluates this
The check is a JSON graph query using a `not_regex_match` operator against the `RUN` instruction's `value` (full shell command text):

- FAIL: the command text matches the pattern `rpm ... --no(digest|signature|verify|filedigest)` (i.e., an `rpm` invocation, not immediately followed by a pipe/`&`/`;`, using one of those four flags anywhere before the match).
- PASS: no `rpm` command in the `RUN` instruction uses any of those four flags.

## Non-compliant example
```dockerfile
FROM centos:7

COPY mypackage.rpm /tmp/mypackage.rpm
RUN rpm -ivh --nosignature --nodigest /tmp/mypackage.rpm
```

## Remediated example
```dockerfile
FROM centos:7

COPY mypackage.rpm /tmp/mypackage.rpm
# Removed --nosignature/--nodigest: signatures and digests are now verified
RUN rpm -ivh /tmp/mypackage.rpm
```

## Remediation steps
1. Remove `--nodigest`, `--nosignature`, `--noverify`, and `--nofiledigest` from all `rpm` invocations.
2. Ensure the vendor's GPG public key is imported into the image (`rpm --import <key>`) before installing signed packages, so verification succeeds instead of failing outright.
3. If a package genuinely has no valid signature (e.g., an internally built, unsigned RPM), sign it internally with your own trusted key rather than disabling verification wholesale.
4. Pin package sources to trusted, HTTPS-served repositories to reduce the risk of a tampered package needing these flags to install in the first place.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunRpmNoSignature.json)
