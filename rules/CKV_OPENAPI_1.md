# CKV_OPENAPI_1: Ensure that securityDefinitions is defined and not empty - version 2.0 files

## Severity
**HIGH** (score: 7.8/10)

An OpenAPI 2.0 spec with no securityDefinitions declares an API with no authentication mechanism at all, meaning any documented endpoint could be implemented and consumed without enforced auth controls.

## Summary
This check ensures that an OpenAPI/Swagger 2.0 specification document defines a non-empty top-level `securityDefinitions` object, meaning the API declares at least one authentication/authorization scheme.

## Applicability
**Checkov framework(s):** `openapi`

- **Framework:** OpenAPI (Swagger 2.0 specification documents)
- **Entity:** `securityDefinitions` (document-level block)

## Why it matters
`securityDefinitions` is where a Swagger 2.0 document declares the authentication mechanisms available to the API (API key, OAuth2, Basic auth, etc.), which operations then reference via `security` requirements. An API specification with no `securityDefinitions` at all signals that the API contract does not describe any authentication scheme — either the API is genuinely unauthenticated (a serious concern for anything beyond a purely public, non-sensitive endpoint), or the spec was written/generated without properly documenting the security model that the real implementation actually enforces. Either way, this is a documentation-and-design red flag: API consumers, security reviewers, and automated tooling (contract testing, API gateways generating policy from the spec) have no way to know what authentication is required, which can lead to APIs being deployed or gatewayed without the intended access controls, or client integrations that assume no auth is needed when the backend actually expects credentials.

## How Checkov evaluates this
This is a graph/document-level Python check (`BaseOpenapiCheckV2`, evaluated at `BlockType.DOCUMENT`) that inspects the parsed OpenAPI document's `securityDefinitions` key:
- FAILS if `"securityDefinitions"` is not present in the document at all.
- FAILS if `securityDefinitions` is present but empty, or is not a proper mapping (`DictNode`) and has 2 or fewer elements (the length-2 check accounts for parser line-metadata artifacts like `__start_line__`/`__end_line__` that Checkov's YAML/JSON parser injects, so a "real" dict with actual content is distinguished from an effectively empty one).
- PASSES otherwise (i.e., a non-empty `securityDefinitions` object is present).

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
paths:
  /users:
    get:
      responses:
        "200":
          description: OK
# securityDefinitions is missing entirely
```

## Remediated example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
securityDefinitions:
  ApiKeyAuth:
    type: apiKey
    in: header
    name: X-API-Key
paths:
  /users:
    get:
      security:
        - ApiKeyAuth: []
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Add a top-level `securityDefinitions` object to the Swagger 2.0 document describing the actual authentication scheme(s) your API implementation enforces (e.g., `apiKey`, `basic`, or `oauth2`).
2. Reference the defined scheme(s) from each operation's `security` array so the spec accurately reflects which endpoints require which credentials.
3. If the API is genuinely and intentionally public/unauthenticated end-to-end, document that explicitly in the spec's description rather than simply omitting `securityDefinitions`, and consider suppressing this check for that specific file with a clear justification comment.
4. Keep the spec in sync with the actual API gateway/auth-middleware configuration to avoid drift between documented and enforced security.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/SecurityDefinitions.py)
