# CKV_OPENAPI_6: Ensure that security requirement defined in securityDefinitions - version 2.0 files

## Severity
**HIGH** (score: 7.5/10)

A security requirement that references a scheme name absent from securityDefinitions means the intended access control is undefined and cannot actually be enforced, effectively leaving the operation unprotected.

## Summary
For Swagger 2.0 documents, every scheme name referenced in any `security` requirement (global or per-operation) must correspond to an entry actually declared in `securityDefinitions`; dangling references indicate a broken or misconfigured security model.

## Applicability
- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `security`, cross-checked against the document's `securityDefinitions` and `paths`.

## Why it matters
If a `security` requirement references a scheme name that was never defined in `securityDefinitions`, then tooling that generates enforcement code (API gateways, server stubs, client SDKs) from the spec has no definition to act on for that name. Depending on the tool, this can fail silently — treating the undefined scheme as "no requirement" — which means the endpoint ends up unauthenticated in practice even though the spec author believed they had locked it down. This is a documentation/implementation drift bug that directly undermines the reliability of "spec as source of truth" for access control, and it typically results from a rename or typo in `securityDefinitions` that wasn't propagated to all `security` usages.

## How Checkov evaluates this
The check (`SecurityRequirement`, a document-level `BaseOpenapiCheckV2`):
1. **FAILS** immediately if `securityDefinitions` is missing from the document entirely.
2. Validates the root-level `security` field: if it is present and non-empty, every scheme key it references must exist in `securityDefinitions`; if any key is not found there, it **FAILS**.
3. **FAILS** if `paths` is missing or not a dict.
4. For every operation under every path, if that operation's own `security` field is present and non-empty, every scheme key must also exist in `securityDefinitions`; a missing key **FAILS**.
5. Passes only when `securityDefinitions` exists and all `security` requirements (root and operation-level) reference only defined scheme names.

## Non-compliant example
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
  /items:
    get:
      security:
        - apiKeyAuthTypo: []
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
  /items:
    get:
      security:
        - apiKeyAuth: []
      responses:
        "200":
          description: OK
```

## Remediation steps
1. List every scheme name used across the document's root `security` and every operation's `security` field.
2. Confirm each name exactly matches a key defined in `securityDefinitions` (names are case-sensitive).
3. Fix typos, or add the missing scheme definition if it was simply never declared.
4. Add automated linting (e.g. a pre-commit hook running Checkov or an OpenAPI linter) to catch this drift early, since it commonly reappears after refactors/renames.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/SecurityRequirement.py
