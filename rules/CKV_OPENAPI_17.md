# CKV_OPENAPI_17: Ensure that operation objects have 'consumes' field defined for PUT, POST and PATCH operations - version 2.0 files

## Severity
**MEDIUM** (score: 5.0/10)

A missing 'consumes' declaration for write operations is a documentation/schema-hygiene gap rather than a directly exploitable weakness.

## Summary
For Swagger 2.0 documents, every `PUT`, `POST`, or `PATCH` operation must explicitly declare a `consumes` field listing the MIME type(s) of request bodies it accepts.

## Applicability
**Checkov framework(s):** `openapi`

- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `paths` (each `PUT`/`POST`/`PATCH` operation object).

## Why it matters
Leaving `consumes` undefined on a body-accepting operation means the API contract does not constrain what content types the server will parse. This is a real security concern: servers that accept an undeclared/unbounded range of content types are more susceptible to content-type confusion attacks, such as sending JSON payloads as `multipart/form-data` or `application/x-www-form-urlencoded` to bypass input validation or CSRF protections that assume `application/json` only, or exploiting a parser that unexpectedly accepts XML (with XXE risk) because the API never restricted itself to JSON. Declaring `consumes` explicitly lets API gateways, WAFs, and server frameworks reject requests with unexpected content types before they ever reach business logic, shrinking the attack surface.

## How Checkov evaluates this
The check (`OperationObjectConsumesUndefined`, a document-level `BaseOpenapiCheckV2`):
1. Reads `paths`.
2. Iterates every operation under every path.
3. For any operation whose method name (case-insensitively) is `post`, `put`, or `patch`, checks whether its `consumes` field is truthy (non-empty).
4. If `consumes` is missing or empty for such an operation, the check **FAILS**.
5. Non-dict path/operation structures yield `UNKNOWN`.
6. Otherwise **PASSES**.

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
paths:
  /items:
    post:
      parameters:
        - in: body
          name: item
          schema:
            type: object
      responses:
        "201":
          description: Created
```

## Remediated example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
paths:
  /items:
    post:
      consumes:
        - application/json
      parameters:
        - in: body
          name: item
          schema:
            type: object
      responses:
        "201":
          description: Created
```

## Remediation steps
1. Add a `consumes` array to every `POST`/`PUT`/`PATCH` operation listing the exact request content type(s) the server actually parses (e.g. `application/json`).
2. Configure the server-side framework/middleware to reject requests whose `Content-Type` header does not match the declared `consumes` list, so the contract is enforced, not just documented.
3. Avoid declaring overly broad `consumes` lists (e.g. `*/*`) purely to pass the check — that reintroduces the ambiguity this rule is meant to eliminate.
4. If different operations genuinely accept different content types (e.g. a file-upload endpoint using `multipart/form-data` vs a JSON endpoint), declare each precisely rather than using a single global default.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/OperationObjectConsumesUndefined.py
