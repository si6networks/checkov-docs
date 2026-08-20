# CKV_OPENAPI_10: Ensure that operation object does not use 'password' flow in OAuth2 authentication - version 2.0 files

## Severity
**HIGH** (score: 7.5/10)

The OAuth2 'password' grant flow requires the client to directly handle and transmit user credentials, undermining OAuth2's core security model and increasing risk of credential exposure or mishandling.

## Summary
This check ensures that no operation in a Swagger 2.0 OpenAPI specification uses the OAuth2 "password" grant flow (Resource Owner Password Credentials) for authentication.

## Applicability
**Checkov framework(s):** `openapi`

- **Framework:** OpenAPI (Swagger 2.0 specification documents)
- **Entity:** `paths` (operations within the document, cross-referenced with `securityDefinitions`)

## Why it matters
The OAuth2 "password" grant (Resource Owner Password Credentials, ROPC) requires the client application to directly collect the end user's raw username and password and forward them to the authorization server to obtain a token. This defeats the core security benefit of OAuth2 — that the client never sees the user's actual credentials — and instead trains users to enter their password into arbitrary first- or third-party client applications, which is precisely the pattern phishing and credential-harvesting attacks exploit. It also makes it impossible for the authorization server to enforce modern protections like enforced MFA/step-up authentication or WebAuthn during the flow, since there's no interactive browser-based authentication step. The OAuth 2.0 Security Best Current Practice (RFC 9700) explicitly deprecates the password grant, recommending clients use the Authorization Code flow (with PKCE) instead. A spec that documents operations using the password flow is effectively codifying a legacy, high-risk authentication pattern into the API contract.

## How Checkov evaluates this
This is a document-level Python check (`BaseOpenapiCheckV2`, evaluated at `BlockType.DOCUMENT`) that cross-references `paths` and `securityDefinitions`:
1. It iterates every path and every operation (method) within that path.
2. For each operation, it reads the `security` array (the list of security requirements applied to that operation).
3. For each named security requirement, it looks up the matching entry in the document's top-level `securityDefinitions`.
4. If that security definition's `type` is `oauth2` (case-insensitive) and its `flow` field equals `"password"`, the check FAILS immediately, returning the offending `auth_definition`.
5. If no operation/security-definition pair uses the password flow, the check PASSES.
6. If the document structure is malformed (e.g., a path or operation is not a dict where expected), the result is UNKNOWN rather than PASS/FAIL.

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
securityDefinitions:
  OAuth2Password:
    type: oauth2
    flow: password
    tokenUrl: https://auth.example.com/oauth/token
    scopes:
      read: Read access
paths:
  /users:
    get:
      security:
        - OAuth2Password: [read]
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
  OAuth2Code:
    type: oauth2
    flow: accessCode
    authorizationUrl: https://auth.example.com/oauth/authorize
    tokenUrl: https://auth.example.com/oauth/token
    scopes:
      read: Read access
paths:
  /users:
    get:
      security:
        - OAuth2Code: [read]
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Identify every `securityDefinitions` entry with `type: oauth2` and `flow: password`.
2. Migrate the authorization server and client applications to the Authorization Code flow with PKCE (`flow: accessCode` in Swagger 2.0 terms, or `authorizationCode` in OpenAPI 3.x), or to the Client Credentials flow for machine-to-machine use cases.
3. Update the `securityDefinitions` block to reflect the new flow, including the required `authorizationUrl` and `tokenUrl`.
4. Update client applications to use a browser/webview-based redirect for the authorization step rather than collecting the user's raw credentials directly.
5. Plan for a coordinated rollout with any third-party integrators who may depend on the password grant, since removing it is a breaking API-contract change for existing clients.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/Oauth2OperationObjectPasswordFlow.py)
