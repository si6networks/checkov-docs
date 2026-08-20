# CKV_OPENAPI_8: Ensure that security is not using 'password' flow in OAuth2 authentication - version 2.0 files

## Severity
**HIGH** (score: 7.5/10)

A global security requirement pointing at an OAuth2 scheme configured with the 'password' grant forces the API's callers to handle raw user credentials directly, increasing credential-exposure and phishing risk.

## Summary
For Swagger 2.0 documents, no `security` requirement should reference an OAuth2 scheme configured with the `flow: password` (Resource Owner Password Credentials) grant type.

## Applicability
- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `security`, cross-referenced against `securityDefinitions`.

## Why it matters
The OAuth2 "Resource Owner Password Credentials" (ROPC) grant requires the client application to directly collect the end user's username and password and forward them to the authorization server. This defeats the core security benefit of OAuth2 — that the client never sees the user's actual credentials — and is explicitly discouraged by IETF (RFC 6749 security considerations, and removed entirely in OAuth 2.1). It re-introduces classic password-handling risks: credentials can be logged, cached, or exfiltrated by a malicious or compromised client; it's incompatible with multi-factor authentication and federated identity; and it trains users to enter passwords into arbitrary third-party apps, enabling phishing. Modern best practice is to use the Authorization Code flow (with PKCE for public clients) so the client never handles the raw password.

## How Checkov evaluates this
The check (`Oauth2SecurityPasswordFlow`, a document-level `BaseOpenapiCheckV2`):
1. Reads the `security` field (defaulting to `[{}]` if unset) and `securityDefinitions`.
2. For each security requirement dict, and each scheme key referenced within it, looks up the corresponding definition in `securityDefinitions`.
3. If that definition's `type` (case-insensitively) is `oauth2` AND its `flow` is exactly `"password"`, the check **FAILS**.
4. If any `security` entry is not a dict, result is `UNKNOWN`.
5. Otherwise **PASSES**.

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
securityDefinitions:
  oauth2Password:
    type: oauth2
    flow: password
    tokenUrl: https://auth.example.com/token
    scopes:
      read: Read access
security:
  - oauth2Password:
      - read
paths:
  /profile:
    get:
      responses:
        "200":
          description: OK
```

## Remediated example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
securityDefinitions:
  oauth2Code:
    type: oauth2
    flow: accessCode
    authorizationUrl: https://auth.example.com/authorize
    tokenUrl: https://auth.example.com/token
    scopes:
      read: Read access
security:
  - oauth2Code:
      - read
paths:
  /profile:
    get:
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Identify every `securityDefinitions` entry with `type: oauth2` and `flow: password`.
2. Migrate to the Authorization Code flow (`flow: accessCode` in Swagger 2.0 terms; `authorizationCode` in OpenAPI 3.x), adding `authorizationUrl` alongside `tokenUrl`.
3. Update client applications to redirect users to the authorization server's login page rather than collecting credentials directly — this typically requires client-side changes, not just spec changes.
4. If the client is a public/native app without a secure redirect, use Authorization Code + PKCE instead of any credential-collecting flow.
5. Remove or deprecate the password-grant client registration on the authorization-server side once migration is complete.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/Oauth2SecurityPasswordFlow.py
- RFC 6749 (OAuth 2.0), Section 4.3 and Section 10: https://www.rfc-editor.org/rfc/rfc6749
