# CKV_OPENAPI_2: Ensure that if the security scheme is not of type 'oauth2', the array value must be empty - version 2.0 files

## Severity
**LOW** (score: 3.0/10)

This is primarily an OpenAPI 2.0 spec-conformance check ensuring non-OAuth2 security schemes carry no scope array; a violation is confusing but does not by itself open a new attack path.

## Summary
For OpenAPI/Swagger 2.0 documents, if a `security` requirement references a scheme whose `type` in `securityDefinitions` is anything other than `oauth2`, the associated scope array in that security requirement must be empty (`[]`), since only OAuth2 uses scopes.

## Applicability
- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** the `security` field (global `security` array or an operation-level `security` array), cross-referenced against `securityDefinitions`.

## Why it matters
The OpenAPI 2.0 spec defines `scopes` as meaningful only for `oauth2`-type security schemes; scopes represent the OAuth2 authorization grants an operation requires. If a non-OAuth2 scheme (e.g. `apiKey`, `basic`) is declared with a non-empty scope list in a `security` requirement, this is a specification error that signals confusion in the security model — the document author likely intended access restrictions that are never actually enforced, since API key/basic auth mechanisms have no concept of scopes. Tools and gateways that generate authorization logic from the spec may silently ignore the (meaningless) scopes, creating a gap between the documented and the actual access-control behavior — i.e., a reviewer or client believes an endpoint is scope-restricted when it is not.

## How Checkov evaluates this
The check (`Oauth2SecurityRequirement`, a `BaseOpenapiCheckV2` document-level check):
1. Reads `securityDefinitions` and builds a list of `non_oauth2_keys` — every security-scheme name whose `type` (case-insensitively) is not `"oauth2"`.
2. Iterates over each requirement in the `security` array (defaulting to `[{}]` if unset).
3. For each key in a security requirement dict, if that key belongs to `non_oauth2_keys` AND its associated value (the scope list) is non-empty (truthy), the check **FAILS**.
4. If any entry in `security` is not a dict, the result is `UNKNOWN`.
5. Otherwise it **PASSES**.

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
security:
  - apiKeyAuth:
      - read:items
      - write:items
paths:
  /items:
    get:
      security:
        - apiKeyAuth:
            - read:items
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
security:
  - apiKeyAuth: []
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
1. For every `security` requirement (global or per-operation) that references a non-OAuth2 scheme, set the scope array to `[]`.
2. If you actually need scope-based access control, switch the scheme's `type` to `oauth2` and define proper `flow`/`scopes` in `securityDefinitions`.
3. Re-run Checkov to confirm the empty-array fix passes for all affected `security` blocks (both global and operation-level).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/Oauth2SecurityRequirement.py
