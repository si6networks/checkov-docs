# CKV_OPENAPI_13: Ensure security definitions do not use basic auth - version 2.0 files

## Severity
**HIGH** (score: 7.5/10)

HTTP Basic authentication sends credentials as trivially-reversible base64 on every request, so any missing or misconfigured TLS hop anywhere in the path exposes the raw username and password.

## Summary
For Swagger 2.0 documents, no entry in `securityDefinitions` should have `type: basic` (HTTP Basic authentication).

## Applicability
- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `securityDefinitions`.

## Why it matters
HTTP Basic authentication transmits the username and password Base64-encoded (not encrypted) on every single request. Base64 is trivially decodable, so if traffic is intercepted at any point — a misconfigured proxy, a compromised network segment, application logs that capture the `Authorization` header, or browser/HTTP client caching — the raw credentials are exposed. Basic auth also has no native support for expiration, revocation, scoping, or multi-factor authentication, making stolen credentials fully and indefinitely usable until manually changed. Declaring a `basic`-type scheme in the spec at all creates the possibility that some client/environment uses it over a non-TLS connection or logs it inadvertently, so removing the definition prevents that risk from ever materializing.

## How Checkov evaluates this
The check (`SecurityDefinitionBasicAuth`, a document-level `BaseOpenapiCheckV2`):
1. Reads `securityDefinitions`; if it isn't a dict, result is `UNKNOWN`.
2. For each named scheme, if `type` (case-insensitively) is `"basic"`, the check **FAILS**.
3. If an individual definition is not a dict, result is `UNKNOWN`.
4. Otherwise **PASSES**.

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
securityDefinitions:
  basicAuth:
    type: basic
paths:
  /account:
    get:
      security:
        - basicAuth: []
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
  apiKeyAuth:
    type: apiKey
    name: X-API-Key
    in: header
paths:
  /account:
    get:
      security:
        - apiKeyAuth: []
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Replace `type: basic` entries in `securityDefinitions` with a token-based mechanism: `apiKey` (header/cookie token) or `oauth2` with an appropriate flow.
2. Update all `security` requirements (global and per-operation) that reference the removed basic scheme to use the new scheme name.
3. Update client integrations to send the new credential type (e.g. `Authorization: Bearer <token>` or a custom API-key header) instead of Basic auth.
4. If Basic auth cannot be removed immediately due to legacy client constraints, ensure it is only ever exposed over TLS-terminated endpoints and plan a deprecation timeline.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/SecurityDefinitionBasicAuth.py
