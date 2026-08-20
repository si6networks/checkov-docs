# CKV_OPENAPI_15: Ensure that operation objects do not use basic auth - version 2.0 files

## Severity
**HIGH** (score: 7.5/10)

An operation that accepts HTTP Basic auth transmits reversible base64-encoded credentials with every call, increasing exposure if transport-layer protections are ever missing.

## Summary
For Swagger 2.0 documents, no operation's `security` requirement should resolve (via `securityDefinitions`) to a scheme with `type: basic` — this checks usage at the operation level, complementing CKV_OPENAPI_13 which checks the scheme definitions.

## Applicability
**Checkov framework(s):** `openapi`

- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `paths` (each operation's `security` field, resolved against `securityDefinitions`).

## Why it matters
HTTP Basic authentication sends the username and password Base64-encoded on every call — effectively cleartext, since Base64 provides no confidentiality. Any operation that actually requires this scheme is exposing credentials on every invocation to network eavesdroppers, misconfigured intermediaries, and anything that logs request headers. Checking at the operation level (rather than only the scheme definition) ensures the finding surfaces exactly where the risk is live: an operation actively relying on Basic auth to authenticate its callers, as opposed to a merely-declared-but-unused scheme.

## How Checkov evaluates this
The check (`OperationObjectBasicAuth`, a document-level `BaseOpenapiCheckV2`):
1. Reads `paths` and `securityDefinitions`.
2. Iterates every operation under every path.
3. For each operation's `security` list, and each scheme key referenced within each requirement, resolves the scheme in `securityDefinitions`.
4. If that scheme's `type == "basic"` (exact match, not case-insensitive in this implementation), the check **FAILS**.
5. Non-dict path/operation structures yield `UNKNOWN`.
6. Otherwise **PASSES**.

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
  /reports:
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
  bearerAuth:
    type: apiKey
    name: Authorization
    in: header
paths:
  /reports:
    get:
      security:
        - bearerAuth: []
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Find every operation whose `security` requirement resolves to a `type: basic` scheme.
2. Switch those operations to reference a token-based scheme instead (`apiKey` header/cookie, or OAuth2).
3. Update the API server's authentication middleware for those specific routes to validate the new credential type.
4. Coordinate the change with client teams, since this is a breaking change to how those endpoints authenticate.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/OperationObjectBasicAuth.py
