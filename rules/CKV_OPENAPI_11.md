# CKV_OPENAPI_11: Ensure that operation object does not use 'password' flow in OAuth2 authentication - version 2.0 files

## Severity
**HIGH** (score: 7.5/10)

OAuth2 'password' grant requires the client application to directly collect and transmit the user's raw credentials, increasing phishing and credential-exposure risk compared to redirect-based flows.

## Summary
For Swagger 2.0 documents, no scheme declared in `securityDefinitions` should be configured with `type: oauth2` and `flow: password` — this checks the security-scheme definitions themselves, complementing CKV_OPENAPI_8 which checks their usage in `security` requirements.

## Applicability
- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `securityDefinitions`.

## Why it matters
The Resource Owner Password Credentials (ROPC) grant (`flow: password`) requires the client to collect and forward the user's raw username/password to obtain a token. This defeats the fundamental OAuth2 design goal of never exposing user credentials to the client application, making credential theft trivial if the client is compromised or malicious, and it's incompatible with MFA/federated login. IETF explicitly discourages ROPC in RFC 6749's security considerations, and it was removed entirely from OAuth 2.1. By checking the definition itself (rather than only its use), this rule catches the problem even before any operation references the scheme — preventing the risky flow from being available for future use in the spec at all.

## How Checkov evaluates this
The check (`Oauth2SecurityDefinitionPasswordFlow`, a document-level `BaseOpenapiCheckV2`):
1. Reads `securityDefinitions`.
2. For each named scheme, if `type` (case-insensitively) is `oauth2` and `flow == "password"`, the check **FAILS**.
3. If a definition is not a dict, result is `UNKNOWN`.
4. Otherwise **PASSES** (no oauth2/password-flow definitions found).

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
      write: Write access
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
      write: Write access
paths: {}
```

## Remediation steps
1. Remove or replace any `securityDefinitions` entry with `type: oauth2` and `flow: password`.
2. Adopt `flow: accessCode` (Authorization Code) or `flow: implicit` only if legacy constraints truly require it (note: implicit is itself deprecated — see CKV_OPENAPI_12).
3. Update the authorization server configuration and any client integration code to use the new grant type/endpoints.
4. Communicate the breaking change to API consumers, since switching grant types generally requires client-side code changes (redirect handling, PKCE, etc.).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/Oauth2SecurityDefinitionPasswordFlow.py
- RFC 6749 (OAuth 2.0), Section 10.7: https://www.rfc-editor.org/rfc/rfc6749
