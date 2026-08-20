# CKV2_DOCKER_14: Ensure that certificate validation isn't disabled for git by setting the environment variable 'GIT_SSL_NO_VERIFY' to any value

## Severity
**HIGH** (score: 7.5/10)

GIT_SSL_NO_VERIFY disables TLS certificate checks for git operations, allowing a man-in-the-middle to serve tampered source code or dependencies fetched via git during the image build.

## Summary
This check verifies that the `GIT_SSL_NO_VERIFY` environment variable is never set (to any value) in a Dockerfile, whether via `ARG`/`ENV` or inline in a `RUN` command, since Git treats its mere presence as disabling TLS certificate checks.

## Applicability
**Checkov framework(s):** `dockerfile`

- **Dockerfile**: `ARG`, `ENV`, and `RUN` instructions.

This is a graph-based check using regex matching, evaluated across the three instruction types.

## Why it matters
Git treats `GIT_SSL_NO_VERIFY` as a boolean-like flag whose mere presence (set to essentially any non-empty value) disables TLS certificate verification for all `https://` git operations (clone, fetch, submodule updates) for the remainder of that shell session/build stage. If a Dockerfile clones source code, private repositories, or submodules over HTTPS with this variable set, an attacker able to intercept network traffic (rogue network, compromised DNS, malicious proxy) could serve a completely different, malicious repository or commit history without Git raising any warning. This is a particularly dangerous vector for build pipelines because the fetched code is typically compiled or executed directly as part of the image build — an MITM'd clone can inject arbitrary code straight into the resulting image.

## How Checkov evaluates this
The check is a JSON graph query using regex matching, requiring both of the following to hold:

- FAIL: an `ARG` or `ENV` instruction's value matches `GIT_SSL_NO_VERIFY(=|\s+)\S+` (the variable assigned any non-whitespace value).
- FAIL: a `RUN` instruction's value matches `(export )?GIT_SSL_NO_VERIFY=(\S+|'[^']+'|"[^"]+")` (inline/exported assignment within a shell command).
- PASS: neither pattern is found anywhere in the Dockerfile's `ARG`/`ENV`/`RUN` instructions.

Note that unlike the npm/pip checks, this one does not test for a specific value like `false` — because Git's own semantics treat *any* set value (including `"0"` in some Git versions, though the canonical convention is `1`/`true`) as "disable verification," Checkov flags the variable being set at all.

## Non-compliant example
```dockerfile
FROM alpine/git:latest

ENV GIT_SSL_NO_VERIFY=1
RUN git clone https://github.com/example/private-repo.git /src
```

## Remediated example
```dockerfile
FROM alpine/git:latest

# Removed GIT_SSL_NO_VERIFY: git now validates the server's TLS certificate
RUN git clone https://github.com/example/private-repo.git /src
```

## Remediation steps
1. Remove every `ENV`/`ARG GIT_SSL_NO_VERIFY=...` declaration and any inline `GIT_SSL_NO_VERIFY=... git ...` usage in `RUN` instructions.
2. If the original motivation was an internal Git server with a self-signed or internal-CA certificate, install that CA into the image's trust store (`update-ca-certificates`) instead of disabling verification globally.
3. If a specific host's certificate is problematic, use Git's per-host `http.<url>.sslVerify` config scoped narrowly, and only as a documented, reviewed exception — never a blanket environment variable.
4. Confirm no build-time secret or credential is exposed to a potential MITM as a result of prior use of this flag (e.g., HTTP Basic auth tokens in the clone URL), and rotate any such credentials if this pattern was in use in production builds.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/EnvGitSslNoVerify.json)
