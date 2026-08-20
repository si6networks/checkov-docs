# CKV_OPENAPI_5: Ensure that security operations is not empty.

## Severity
**HIGH** (score: 7.5/10)

An explicitly empty 'security' array on an operation (with no global fallback) disables authentication for that specific endpoint, leaving it reachable without credentials.

## Summary
Every operation in the OpenAPI document must be covered by a non-empty `security` requirement — either declared explicitly on the operation itself, or inherited from a non-empty global `security` field — so that no endpoint is left unauthenticated by omission.

## Applicability
- **IaC framework:** OpenAPI (Swagger 2.0 and OpenAPI 3.x — generic, version-agnostic check).
- **Entity:** `security` at both the document root and the per-operation level, evaluated alongside `paths`.

## Why it matters
This check closes the gap left by relying solely on a global `security` default: even when a global default exists, an operation can explicitly set `security: []` to opt out of it, or simply omit `security` while the root has none either. Either way, the practical effect is an endpoint reachable without any authentication or authorization check. This is one of the most common real-world causes of exposed APIs — a new route added during a sprint, missing the auth decorator/middleware that the rest of the API uses, silently serving data (or accepting writes) to anonymous callers. Automated scanners and attackers routinely enumerate `paths` looking for exactly this condition.

## How Checkov evaluates this
The check (`SecurityOperations`, a document-level `BaseOpenapiCheck`):
1. Reads the root-level `security` field (`root_security`).
2. Iterates every path and every operation (method) beneath `paths`.
3. For each operation, reads its own `security` field (`op_security`):
   - If `op_security` is explicitly present but an **empty list** (`[]`), the check **FAILS** (operation explicitly disables auth).
   - If `op_security` is **absent** (`None`) AND the root-level `security` is also empty/absent, the check **FAILS** (no fallback protection).
4. If every operation either declares its own non-empty security or can fall back to a non-empty root security, the check **PASSES**.

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
security:
  - apiKeyAuth: []
paths:
  /internal/debug:
    get:
      security: []
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
  /internal/debug:
    get:
      security:
        - apiKeyAuth: []
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Audit every operation in the affected spec files for a `security: []` override or a missing `security` field with no covering global default.
2. For each such operation, either remove the local override (letting it inherit the global default) or add an explicit non-empty `security` requirement appropriate to that endpoint.
3. If an endpoint is genuinely meant to be public (e.g. `/healthz`), keep it deliberately annotated (`security: []`) but document the exception and consider excluding it from this check via Checkov skip comments (`#checkov:skip=CKV_OPENAPI_5:reason`) rather than leaving it ambiguous.
4. Re-scan `swagger.json` / `openapi.json` in all three flagged locations to confirm remediation.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/generic/SecurityOperations.py
