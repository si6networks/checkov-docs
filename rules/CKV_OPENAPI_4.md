# CKV_OPENAPI_4: Ensure that the global security field has rules defined

## Severity
**HIGH** (score: 7.5/10)

A completely empty global 'security' field means the document defines no default authentication requirement, so any operation that doesn't declare its own security is effectively left unauthenticated.

## Summary
The document-level (global) `security` field in an OpenAPI/Swagger document must be present and non-empty, meaning at least one authentication/authorization mechanism is required by default for the whole API.

## Applicability
- **IaC framework:** OpenAPI (both Swagger 2.0 and OpenAPI 3.x specification files — this is a "generic" check not tied to a specific version).
- **Entity:** the top-level `security` field of the document.

## Why it matters
The global `security` field establishes the default authentication requirement applied to every operation that doesn't override it. If it is missing or empty, any operation that also fails to declare its own `security` requirement is implicitly unauthenticated. This is a common root cause of accidental open endpoints: a developer adds a new path, forgets to add per-operation security, and — because there's no strict global default — the endpoint is served with no access control at all. An unauthenticated attacker can then invoke the API directly, potentially reading or modifying data, depending on what the endpoint does.

## How Checkov evaluates this
The check (`GlobalSecurityFieldIsEmpty`, a document-level `BaseOpenapiCheck` — applies across spec versions):
1. Reads the top-level `security` field from the parsed document.
2. If it is truthy (present and non-empty, e.g. a list with at least one requirement object), the check **PASSES**.
3. If it is missing, `null`, or an empty list `[]`, the check **FAILS**.

Note this check only inspects the top-level field — it does not look at whether individual operations separately define their own security (that is covered by CKV_OPENAPI_5).

## Non-compliant example
```yaml
openapi: "3.0.0"
info:
  title: Sample API
  version: "1.0"
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      name: X-API-Key
      in: header
paths:
  /items:
    get:
      responses:
        "200":
          description: OK
```

## Remediated example
```yaml
openapi: "3.0.0"
info:
  title: Sample API
  version: "1.0"
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      name: X-API-Key
      in: header
security:
  - apiKeyAuth: []
paths:
  /items:
    get:
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Add a top-level `security` array to the OpenAPI document referencing at least one scheme defined under `components.securitySchemes` (OpenAPI 3.x) or `securityDefinitions` (Swagger 2.0).
2. Choose the default requirement carefully — if some endpoints must remain public (e.g. health checks), keep the global default as the secured baseline and explicitly override with an empty `security: []` on those specific operations, rather than leaving the whole API unauthenticated by default.
3. Regenerate/re-export the spec from your API framework (if it auto-generates OpenAPI docs) after adding auth middleware, to ensure the exported spec reflects the enforced security.
4. Re-scan the updated `swagger.json`/`openapi.json` files with Checkov to confirm the fix resolves the finding across all three flagged files in this repo.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/generic/GlobalSecurityFieldIsEmpty.py
