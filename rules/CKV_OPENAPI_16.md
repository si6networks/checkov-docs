# CKV_OPENAPI_16: Ensure that operation objects have 'produces' field defined for GET operations - version 2.0 files

## Severity
**LOW** (score: 2.0/10)

A missing 'produces' declaration is a schema-completeness/documentation gap for response content types and does not itself expose a reachable attack path.

## Summary
For Swagger 2.0 documents, every `GET` operation must explicitly declare a `produces` field listing the MIME type(s) of its response content, rather than relying on an implicit or undefined content type.

## Applicability
**Checkov framework(s):** `openapi`

- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `paths` (each `GET` operation object).

## Why it matters
An undefined `produces` field leaves the response's `Content-Type` ambiguous in the API contract. This matters for security, not just correctness: many content-sniffing vulnerabilities and MIME-confusion attacks (e.g., a browser or client library interpreting a JSON API response as HTML/JavaScript because no explicit content type was declared, or a reverse proxy/cache defaulting to something unsafe) stem from services that don't declare their response type strictly. Explicitly declaring `produces` also allows API gateways, WAFs, and client SDKs to enforce/validate the expected response type, reducing the attack surface for response-splitting or content-type confusion exploits, and it improves documentation accuracy for consumers building strict parsers.

## How Checkov evaluates this
The check (`OperationObjectProducesUndefined`, a document-level `BaseOpenapiCheckV2`):
1. Reads `paths`; if missing or not a dict, result is `UNKNOWN`.
2. Iterates every operation under every path.
3. For any operation whose method name (case-insensitively) is `get`, checks whether its `produces` field is truthy (non-empty).
4. If `produces` is missing or empty for a `GET` operation, the check **FAILS**.
5. Non-`GET` operations, and non-dict operation objects, are handled accordingly (`UNKNOWN` for malformed operation objects).
6. Otherwise **PASSES**.

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
paths:
  /items:
    get:
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
paths:
  /items:
    get:
      produces:
        - application/json
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Add a `produces` array to every `GET` operation listing the actual MIME type(s) it returns (e.g. `application/json`).
2. If all operations share the same response type, consider declaring `produces` once at the document root — Swagger 2.0 lets operations inherit the global `produces` if they don't override it, though Checkov's rule here specifically checks the per-operation field, so confirm your tooling/spec generator propagates or duplicates it as needed to satisfy the check.
3. Keep `produces` in sync with what the server actually sets in its `Content-Type` response header to avoid spec drift.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/OperationObjectProducesUndefined.py
