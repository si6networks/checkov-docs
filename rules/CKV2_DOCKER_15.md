# CKV2_DOCKER_15: Ensure that the yum and dnf package managers are not configured to disable SSL certificate validation via the 'sslverify' configuration option

## Severity
**HIGH** (score: 7.5/10)

Disabling sslverify for yum/dnf removes certificate validation on RPM repository connections, enabling interception or spoofing of package downloads and installation of malicious packages.

## Summary
This check verifies that no `RUN` instruction disables TLS certificate validation for `yum`/`dnf` package installs via `--setopt=sslverify=0` (or equivalent false/no values).

## Applicability
**Checkov framework(s):** `dockerfile`

- **Dockerfile**: any `RUN` instruction.

This is a graph-based, case-insensitive regex check against the `RUN` instruction's command text.

## Why it matters
`yum`/`dnf`'s `sslverify` option controls whether the package manager validates the TLS certificate presented by the repository server (and any per-repo variant like `<reponame>.sslverify`). Setting it to `0`/`false`/`no` means the package manager will accept connections to any server claiming to be the configured repository, regardless of certificate validity — enabling a network-positioned attacker to serve a malicious repodata/package payload that gets installed directly into the image. As with the analogous npm/rpm checks, this converts a normal, routine dependency-fetch step into a potential remote-code-injection point during the image build, and the compromised result is then baked into every layer built on top of that image.

## How Checkov evaluates this
The check is a JSON graph query using a case-insensitive (`(?i)`) `not_regex_match` operator against the `RUN` instruction's `value`:

- FAIL: the command matches `(yum|dnf)(\s+|-)config-manager ... --setopt=[repo.]sslverify=(0|'0'|"0"|false|'false'|"false"|no|'no'|"no")`.
- PASS: no such `--setopt=...sslverify=<falsy value>` pattern is present.

## Non-compliant example
```dockerfile
FROM centos:8

RUN yum-config-manager --setopt=sslverify=0 --save && \
    yum install -y some-package
```

## Remediated example
```dockerfile
FROM centos:8

# Removed sslverify=0: repository TLS certificates are now validated
RUN yum install -y some-package
```

## Remediation steps
1. Remove `--setopt=sslverify=0` (or any `false`/`no` variant, optionally prefixed with a specific repo name) from all `yum-config-manager`/`dnf config-manager` invocations.
2. If the underlying issue is an internal repository with a self-signed/internal-CA certificate, install the CA into `/etc/pki/ca-trust` and run `update-ca-trust` instead of disabling verification.
3. If a specific repo's certificate is misconfigured, fix that repository's certificate configuration rather than disabling validation client-side across every consuming build.
4. Verify no `.repo` files under `/etc/yum.repos.d/` also set `sslverify=0` directly (this Checkov check only inspects `RUN` command text, not repo file contents dropped in via `COPY`/`ADD`), and fix those as well.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunYumConfigManagerSslVerify.json)
