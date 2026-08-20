# CKV_SECRET_9: JSON Web Token

## Severity
**LOW** (score: 2.0/10)

An exposed JWT can allow an attacker to impersonate the token's subject or bypass authentication for as long as the token remains valid, though impact is bounded by the token's expiry and scope rather than being a permanent credential leak.

## Summary
This check scans files for strings matching the structural format of a JSON Web Token (JWT) — three base64url-encoded segments separated by dots — flagging any match as a potentially hardcoded/leaked token.

## Applicability
**Checkov framework(s):** `secrets`

This is a built-in Checkov **secrets scanning** check (framework: `secrets`) that runs against any text file included in a repository/directory scan — application source, IaC templates, CI/CD pipeline files, configuration files, and plaintext test fixtures. It is content/pattern-based rather than tied to a specific resource type ("entities": `secrets`).

## Why it matters
A JWT is a self-contained, signed (and sometimes encrypted) credential commonly used for authentication and authorization: possession of a valid JWT is often sufficient to impersonate a user or service until the token expires or is revoked. Because JWTs frequently carry claims such as user identity, roles/scopes, and issuer information directly readable in their base64url-encoded payload segment, a leaked token exposes both a working credential and information about the system's authorization model. Hardcoded JWTs in source (e.g. test fixtures using real tokens, or tokens embedded in scripts/CI config for convenience) risk being replayed by anyone with repository read access — and unlike an API key, an unexpired JWT typically cannot be revoked individually without revoking the entire signing key or session store, making cleanup after a leak more disruptive.

## How Checkov evaluates this
Checkov uses the `detect-secrets` plugin architecture; the `JwtTokenDetector` plugin registered for this check applies a regular expression matching the standard JWT structure — `<base64url-header>.<base64url-payload>.<base64url-signature>` — against each line of a scanned file, along with a sanity check that the decoded header/payload segments look like valid JSON. A structural match causes Checkov to report **FAILED** for `CKV_SECRET_9` at that location. Lines without a matching three-segment JWT-shaped string produce no finding.

## Non-compliant example
```yaml
# ci-config.yaml — a live JWT hardcoded as a test/auth token
steps:
  - name: call-api
    env:
      AUTH_TOKEN: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PDO0h6bcH8Q0"
    command: "curl -H \"Authorization: Bearer $AUTH_TOKEN\" https://api.internal.example.com"
```

## Remediated example
```yaml
# ci-config.yaml — token is sourced from CI secret storage at run time
steps:
  - name: call-api
    env:
      AUTH_TOKEN: "${{ secrets.API_AUTH_TOKEN }}"
    command: "curl -H \"Authorization: Bearer $AUTH_TOKEN\" https://api.internal.example.com"
```

## Remediation steps
1. If the flagged JWT is a real, valid token, treat it as compromised: revoke the underlying session/refresh token or rotate the signing key if revocation per-token is not supported.
2. Remove the literal token from the file and purge it from git history (`git filter-repo` / BFG Repo-Cleaner).
3. Source tokens at runtime from CI/CD secret stores, environment variables, or a secrets manager rather than embedding them in config or test fixtures.
4. For test fixtures that need a JWT-shaped value, generate a clearly-fake token (invalid signature, dummy claims, obviously non-production issuer) and add it to the `detect-secrets` baseline as a verified false positive rather than using a real token.
5. Add pre-commit secret scanning to catch tokens before they are committed, especially in test suites where developers often paste real tokens for convenience during debugging.
6. Prefer short-lived tokens and refresh-token rotation in the application's auth design so any future leak has a bounded window of usefulness.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py
