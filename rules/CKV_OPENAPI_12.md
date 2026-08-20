# CKV_OPENAPI_12: Ensure no security definition is using implicit flow on OAuth2, which is deprecated - version 2.0 files

## Severity
**MEDIUM** (score: 5.0/10)

OAuth2 'implicit' flow returns access tokens directly in the URL fragment, exposing them to browser history, referrer headers, and server logs instead of a secure back-channel exchange.

## Summary
For Swagger 2.0 documents, no scheme in `securityDefinitions` should use `type: oauth2` with `flow: implicit`, since the Implicit grant is deprecated in modern OAuth2 practice.

## Applicability
**Checkov framework(s):** `openapi`

- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `securityDefinitions`.

## Why it matters
The OAuth2 Implicit grant returns the access token directly in the browser's URL fragment after redirect, without a server-side token exchange or client authentication step. This design has several well-documented weaknesses: tokens can leak via browser history, HTTP `Referer` headers, or malicious browser extensions/JavaScript; there is no refresh-token support, forcing frequent re-authentication or unsafe long-lived tokens; and because the fragment is never sent to the server, there is no way to detect or prevent token leakage in transit. The OAuth Security Best Current Practice (BCP) and OAuth 2.1 both recommend deprecating the Implicit flow in favor of the Authorization Code flow with PKCE, which keeps the token exchange server-side (or PKCE-protected) and eliminates the token-in-URL exposure.

## How Checkov evaluates this
The check (`Oauth2SecurityDefinitionImplicitFlow`, a document-level `BaseOpenapiCheckV2`):
1. Reads `securityDefinitions`.
2. For each named scheme, if `type` (case-insensitively) is `oauth2` and `flow == "implicit"`, the check **FAILS**.
3. If a definition is not a dict, result is `UNKNOWN`.
4. Otherwise **PASSES**.

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
securityDefinitions:
  oauth2Implicit:
    type: oauth2
    flow: implicit
    authorizationUrl: https://auth.example.com/authorize
    scopes:
      read: Read access
paths: {}
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
paths: {}
```

## Remediation steps
1. Replace any `flow: implicit` OAuth2 definition with `flow: accessCode` (Swagger 2.0's name for Authorization Code) and add the required `tokenUrl`.
2. For single-page apps / mobile clients that cannot securely hold a client secret, use Authorization Code with PKCE at the authorization-server level (Swagger 2.0 itself has no PKCE flag; document the requirement operationally and enforce it server-side).
3. Update front-end code to perform the code-exchange step (typically via a backend-for-frontend or a public client using PKCE) instead of parsing the token from the redirect fragment.
4. Rotate/revoke any long-lived tokens that may have been issued under the old implicit flow once migration is complete.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/Oauth2SecurityDefinitionImplicitFlow.py
- OAuth 2.0 Security Best Current Practice (IETF draft, recommends against Implicit): https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
