# CKV_OPENAPI_9: Ensure that security scopes of operations are defined in securityDefinitions - version 2.0 files
## Severity
**MEDIUM** (score: 5.0/10)

Undefined security scopes break the authoritative link between an operation's declared authorization requirements and the spec's securityDefinitions, risking tooling that silently treats unresolved scopes as unrestricted and producing incorrect authorization documentation, though the API's actual runtime enforcement is not directly altered by the spec alone.

## Summary
This check ensures that every OAuth2 security scope referenced by an operation in an OpenAPI 2.0 (Swagger) document is actually declared in the top-level `securityDefinitions` block, so that access-control scopes used in the API cannot silently be undefined or mistyped.

## Applicability
Applies to OpenAPI (Swagger) 2.0 specification files. Checkov evaluates the `paths` object of the document (entity type `paths`), examining each path's operations and their `security` requirements against the document-level `securityDefinitions`.

## Why it matters
OpenAPI 2.0 lets each operation declare which OAuth2 scopes a caller must hold via a `security` block (e.g. `security: [{ oauth2_auth: [write_pets] }]`). The actual set of valid scopes for a given security scheme is only defined once, in `securityDefinitions`. If an operation references a security definition name that doesn't exist, or references a scope that was never declared (or was declared with a typo), several dangerous outcomes are possible:

- Some API gateways/tooling treat an undefined or unrecognized scope requirement as "no restriction," silently downgrading an endpoint from access-controlled to open.
- Client SDK/documentation generators built from the spec may produce incorrect or misleading authorization guidance for API consumers.
- Contract/schema-drift: the spec no longer accurately documents the authorization model actually implemented by the API, defeating the purpose of using OpenAPI as a security-relevant source of truth.

Because the whole point of securityDefinitions + scopes is to give a single authoritative list of valid authorization scopes, any operation-level reference that doesn't resolve back to that list is effectively an authorization control that can't be verified or enforced correctly.

## How Checkov evaluates this
The check (`OperationObjectSecurityScopeUndefined`) walks the `paths` object of the parsed document:

1. For each path, and for each operation (`get`, `post`, etc.) under that path, it reads the operation's `security` list (defaulting to `[{}]` if absent).
2. For each security requirement dict, it iterates over each `auth_key` (the name of a security scheme referenced by the operation) and its associated `auth_scopes` (list of required scopes).
3. It looks up `auth_key` in the document's `securityDefinitions`. **FAIL** if the auth_key has no corresponding definition (`auth_definition` is empty/falsy).
4. If the definition's `type` is not `"oauth2"`, the scopes check doesn't apply and it moves on (only oauth2 schemes carry scopes).
5. For oauth2 definitions, it reads `definition_scopes` (the `scopes` map declared under that security definition). **FAIL** if `definition_scopes` is empty despite the operation requiring scopes.
6. For each scope listed in the operation's `auth_scopes`, **FAIL** if that scope string is not a key in `definition_scopes`.
7. If every referenced security definition exists, is properly scoped, and every requested scope is declared, the check **PASSES**.
8. Malformed structures (non-dict paths/operations/security entries) return `UNKNOWN` rather than pass/fail.

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Pet Store API
  version: "1.0"
securityDefinitions:
  oauth2_auth:
    type: oauth2
    flow: implicit
    authorizationUrl: https://example.com/oauth/authorize
    scopes:
      read_pets: Read access to pets

paths:
  /pets:
    post:
      summary: Create a pet
      security:
        - oauth2_auth:
            - write_pets   # scope not declared under securityDefinitions.oauth2_auth.scopes
      responses:
        "201":
          description: Created
```

## Remediated example
```yaml
swagger: "2.0"
info:
  title: Pet Store API
  version: "1.0"
securityDefinitions:
  oauth2_auth:
    type: oauth2
    flow: implicit
    authorizationUrl: https://example.com/oauth/authorize
    scopes:
      read_pets: Read access to pets
      write_pets: Write access to pets   # scope now declared

paths:
  /pets:
    post:
      summary: Create a pet
      security:
        - oauth2_auth:
            - write_pets   # matches a declared scope
      responses:
        "201":
          description: Created
```

## Remediation steps
1. Enumerate every scope referenced anywhere in `security` blocks across your `paths`.
2. Ensure the corresponding `securityDefinitions.<name>` entry exists for each `auth_key` used.
3. For `type: oauth2` definitions, add every referenced scope to the `scopes` map with a human-readable description.
4. Double-check for typos between the scope name used in an operation's `security` block and the key used under `scopes` — they must match exactly (case-sensitive).
5. If a security scheme doesn't require scopes (e.g. `apiKey` or `basic` type), scopes aren't applicable — the check skips non-oauth2 definitions automatically.
6. Re-run Checkov or validate with a Swagger/OpenAPI 2.0 linter to confirm no dangling scope references remain.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/OperationObjectSecurityScopeUndefined.py
