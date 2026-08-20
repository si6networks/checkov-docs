# CKV2_DOCKER_16: Ensure that certificate validation isn't disabled with pip via the 'PIP_TRUSTED_HOST' environment variable

## Severity
**MEDIUM** (score: 5.0/10)

PIP_TRUSTED_HOST disables TLS certificate verification for pip installs from the named host, exposing the Python dependency chain to man-in-the-middle package tampering during the build.

## Summary
This check verifies that the `PIP_TRUSTED_HOST` environment variable is never set in a Dockerfile, whether via `ARG`/`ENV` or inline in a `RUN` command, since it tells pip to skip HTTPS certificate verification for the listed host(s).

## Applicability
**Checkov framework(s):** `dockerfile`

- **Dockerfile**: `ARG`, `ENV`, and `RUN` instructions.

This is a graph-based check using regex matching, evaluated across the three instruction types.

## Why it matters
`PIP_TRUSTED_HOST` (equivalent to pip's `--trusted-host` CLI flag) instructs pip to treat connections to the named host as trusted even if the TLS certificate cannot be verified — effectively disabling certificate validation for that host. If set for a package index (PyPI, an internal index, or a mirror), an attacker able to intercept traffic to that host (DNS poisoning, ARP spoofing on a shared network, compromised transparent proxy) can serve arbitrary package files, and pip will install them without complaint. Since Python packages routinely execute arbitrary code at install time (`setup.py`, build backends), a single MITM'd install is equivalent to remote code execution during the image build — and, again, the result is permanently embedded in the built image.

## How Checkov evaluates this
The check is a JSON graph query requiring both of the following to hold:

- FAIL: a `RUN` instruction's value matches `(export )?PIP_TRUSTED_HOST=(\S+|'[^']+'|"[^"]+")` (inline/exported assignment).
- FAIL: an `ARG` or `ENV` instruction's value matches `PIP_TRUSTED_HOST(=|\s+)\S+` (the variable assigned any value).
- PASS: neither pattern is found anywhere in the Dockerfile's `ARG`/`ENV`/`RUN` instructions.

As with `GIT_SSL_NO_VERIFY`, the check flags the variable being set at all, since its presence (naming any host) is itself the security-relevant condition — pip does not require a specific "true/false" value here, only a hostname to trust unconditionally.

## Non-compliant example
```dockerfile
FROM python:3.12

ENV PIP_TRUSTED_HOST=pypi.org
RUN pip install requests
```

## Remediated example
```dockerfile
FROM python:3.12

# Removed PIP_TRUSTED_HOST: pip now validates the index's TLS certificate
RUN pip install requests
```

## Remediation steps
1. Remove every `ENV`/`ARG PIP_TRUSTED_HOST=...` declaration and any inline `PIP_TRUSTED_HOST=... pip ...` usage in `RUN` instructions.
2. If the motivation was an internal package index with a self-signed/internal-CA certificate, install that CA into the system trust store (`update-ca-certificates`) or point pip at a custom CA bundle via `PIP_CERT`, rather than disabling verification for the host entirely.
3. If the index is a corporate TLS-intercepting proxy, prefer configuring the proxy's CA in the trust store over trusting the host unconditionally.
4. Audit any `pip.conf`/`pip.ini` files copied into the image (via `COPY`) for a `trusted-host` setting as well — this Checkov check only inspects `ARG`/`ENV`/`RUN` instructions, not the contents of config files added to the image.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/EnvPipTrustedHost.json)
