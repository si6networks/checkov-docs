# CKV2_DOCKER_4: Ensure that certificate validation isn't disabled with the pip '--trusted-host' option
## Severity
**HIGH** (score: 7.5/10)

pip's --trusted-host flag bypasses TLS certificate verification for Python package installs, letting a network attacker serve a malicious wheel/sdist that executes arbitrary code during the build and persists in the image.

## Summary
This check fails a Dockerfile if any `RUN` instruction invokes `pip`/`pip3` with the `--trusted-host` option, which tells pip to skip TLS certificate verification for the named package index host.

## Applicability
Applies to `Dockerfile` builds. Implemented as a Checkov graph-based JSON policy scanning `RUN` instructions (`resource_types: ["RUN"]`).

## Why it matters
`pip install --trusted-host <host>` disables HTTPS certificate validation when talking to that host (commonly used to work around self-signed internal PyPI mirrors or proxy interception). Because pip downloads and then *executes* arbitrary Python code (via `setup.py`/build backends) as part of installing a package, a MITM attacker able to intercept traffic to the trusted host can substitute a malicious wheel or sdist, resulting in arbitrary code execution during the image build — typically as root. This is a supply-chain attack vector: unlike a corrupted static file, a tampered Python package can execute install-time hooks that establish persistence, exfiltrate build secrets (environment variables, mounted credentials), or modify other layers being built in the same stage.

## How Checkov evaluates this
Single `attribute` condition on `RUN` instructions: the instruction's `value` must **not** match
```
.*(pip3?[^\|&;]*\s+--trusted-host).*
```
i.e. `pip` or `pip3` followed (within the same shell command segment, not separated by `|`, `&`, `;`) by the `--trusted-host` flag. A match **FAILs**; its absence **PASSes**.

## Non-compliant example
```dockerfile
FROM python:3.12-slim
RUN pip install --index-url https://internal-pypi.corp.local/simple \
    --trusted-host internal-pypi.corp.local \
    myinternalpkg==1.4.2
```

## Remediated example
```dockerfile
FROM python:3.12-slim
# Trust the internal mirror's real CA instead of skipping verification
COPY internal-ca.crt /usr/local/share/ca-certificates/internal-ca.crt
RUN update-ca-certificates && \
    pip install --index-url https://internal-pypi.corp.local/simple \
    myinternalpkg==1.4.2
```

## Remediation steps
1. Remove `--trusted-host` from all `pip`/`pip3` invocations.
2. If the target index uses a self-signed or internal CA, import that CA into the build image's trust store (e.g. via `COPY` + `update-ca-certificates`) rather than disabling validation.
3. Prefer a properly certificate-issued internal PyPI mirror (e.g. via Let's Encrypt or an internal CA that all build hosts already trust).
4. Pin package versions and use `--require-hashes` with a hash-locked requirements file as additional supply-chain protection.
5. Re-run Checkov to confirm.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunPipTrustedHost.json
