# CKV_OPENAPI_19: Ensure that global security scope is defined in securityDefinitions - version 2.0 files

## Severity
**MEDIUM** (score: 5.0/10)

OAuth2 scopes referenced in the global security requirement that are undefined or mismatched in securityDefinitions can produce inconsistent or unintended scope enforcement across the API.

## Summary
For Swagger 2.0 documents, every OAuth2 scope referenced in the root-level `security` field must correspond to a scope actually declared in the matching `securityDefinitions` entry's `scopes` map — undeclared scopes indicate a broken or meaningless access-control declaration.

## Applicability
**Checkov framework(s):** `openapi`

- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `security` (document root), cross-checked against `securityDefinitions`.

## Why it matters
When the global `security` field lists scopes for a scheme (e.g. `oauth2Scheme: [read, write]`), those scope names must exist in that scheme's `scopes` definition for the requirement to be meaningful — the `scopes` map in `securityDefinitions` is where each scope's semantics (what access it actually grants) is declared. If a `security` requirement references a scope that was never defined, tools generating enforcement logic (authorization servers, gateways, SDKs) have no rule to enforce for that name; depending on implementation, this can silently degrade to "no restriction," meaning an endpoint intended to require a specific OAuth2 scope ends up accepting any valid token regardless of its granted scopes. This is a documentation/enforcement drift issue that directly weakens the API's actual access-control posture versus its documented intent.

## How Checkov evaluates this
The check (`GlobalSecurityScopeUndefined`, a document-level `BaseOpenapiCheckV2`):
1. Reads `securityDefinitions` and the root-level `security` field (defaulting to `[{}]`).
2. For each security requirement dict, and each scheme key with a non-empty scope list within it:
   - Looks up the scheme in `securityDefinitions`; if not found, **FAILS**.
   - Reads that scheme's `scopes` map; if missing/empty, **FAILS**.
   - For each scope name listed in the requirement, if it is not a key in the scheme's `scopes` map, **FAILS**.
3. If any `security` entry is not a dict, result is `UNKNOWN`.
4. Otherwise **PASSES**.

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
securityDefinitions:
  oauth2Scheme:
    type: oauth2
    flow: accessCode
    authorizationUrl: https://auth.example.com/authorize
    tokenUrl: https://auth.example.com/token
    scopes:
      read: Read access
security:
  - oauth2Scheme:
      - read
      - write
paths: {}
```

## Remediated example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
securityDefinitions:
  oauth2Scheme:
    type: oauth2
    flow: accessCode
    authorizationUrl: https://auth.example.com/authorize
    tokenUrl: https://auth.example.com/token
    scopes:
      read: Read access
      write: Write access
security:
  - oauth2Scheme:
      - read
      - write
paths: {}
```

## Remediation steps
1. Compare every scope name used in the root-level `security` field against the `scopes` map of the corresponding `securityDefinitions` entry.
2. Add any missing scope to the scheme's `scopes` map with an accurate human-readable description of what it grants.
3. If a scope name was a typo, correct it to match the intended, already-defined scope.
4. Confirm the authorization server that issues tokens actually implements and enforces these same scope names — spec-level scope declarations mean nothing if the token-issuing system doesn't understand them.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/GlobalSecurityScopeUndefined.py
