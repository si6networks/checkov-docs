# CKV_OPENAPI_21: Ensure that arrays have a maximum number of items

## Severity
**MEDIUM** (score: 5.0/10)

Arrays without a maximum item count let a client submit unbounded payloads, creating a resource-exhaustion/denial-of-service risk rather than a confidentiality or integrity breach.

## Summary
Every schema of `type: array` anywhere in the OpenAPI/Swagger document (parameters, request bodies, response schemas, nested definitions) must declare a `maxItems` constraint, so clients cannot submit or trigger unbounded-size arrays.

## Applicability
**Checkov framework(s):** `openapi`

- **IaC framework:** OpenAPI (both Swagger 2.0 and OpenAPI 3.x specification files — generic, version-agnostic check).
- **Entity:** `paths` (recursively scans any nested `array`-typed schema reachable from path/operation definitions, including parameters, request bodies, and response schemas).

## Why it matters
An array schema with no upper bound on element count allows a client to submit (or a server to attempt returning) an arbitrarily large array in a single request or response. This is a classic resource-exhaustion / denial-of-service vector: a request body containing millions of array elements can consume excessive memory or CPU during deserialization, validation, or processing, potentially degrading or crashing the service (an "algorithmic complexity" or "billion laughs"-style attack applied to array payloads rather than XML entities). It also complicates capacity planning and can amplify the cost of downstream operations (e.g., a bulk-insert endpoint that loops over every array element, each triggering a database write). Declaring `maxItems` lets the API framework reject oversized payloads early, before they consume significant resources.

## How Checkov evaluates this
The check (`NoMaximumNumberItems`, a document-level `BaseOpenapiCheck`):
1. Recursively walks the entire `paths` structure (`check_array_max_items`), descending into every dict value and every item of every list value.
2. At any level, if a dict has a `"type"` key equal to `"array"` and no `maxItems` key (or `maxItems` is `None`), the check **FAILS** at that schema.
3. The recursion continues into nested dicts/lists (e.g. `items`, `properties`, parameter schemas, response schemas) until either a violation is found or the entire `paths` tree has been traversed.
4. If no array schema without `maxItems` is found anywhere, the check **PASSES**.

## Non-compliant example
```yaml
openapi: "3.0.0"
info:
  title: Sample API
  version: "1.0"
paths:
  /items:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                tags:
                  type: array
                  items:
                    type: string
      responses:
        "201":
          description: Created
```

## Remediated example
```yaml
openapi: "3.0.0"
info:
  title: Sample API
  version: "1.0"
paths:
  /items:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                tags:
                  type: array
                  items:
                    type: string
                  maxItems: 50
      responses:
        "201":
          description: Created
```

## Remediation steps
1. Search every schema in `paths` (parameters, request bodies, response schemas, and any nested `items`/`properties`) for `type: array` and add an appropriate `maxItems` value based on realistic business limits.
2. Also add `minItems` where a non-empty array is required, to fully bound the input — this check only enforces the upper bound, but pairing both improves validation robustness.
3. Enforce the same limit server-side (not just in the spec) — OpenAPI constraints are documentation/contract, and request validation middleware (or manual checks) must actually reject oversized payloads at runtime.
4. For genuinely unbounded collections (e.g. paginated result sets), ensure pagination is used instead of ever returning/accepting an unbounded array, and set `maxItems` to the page-size cap.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/generic/NoMaximumNumberItems.py
