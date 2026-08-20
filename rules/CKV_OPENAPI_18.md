# CKV_OPENAPI_18: Ensure that global schemes use 'https' protocol instead of 'http' - version 2.0 files

## Severity
**HIGH** (score: 7.5/10)

Declaring 'http' among the global schemes means the entire API, including any credentials, tokens, and sensitive payloads, can be transmitted in cleartext and intercepted on the network.

## Summary
For Swagger 2.0 documents, if a global `schemes` field is declared, it must not include `http` — all globally advertised transport protocols must be encrypted (`https`, and by implication `wss` over `ws`).

## Applicability
- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `schemes` (document root).

## Why it matters
The document-level `schemes` field is the default transport protocol list inherited by every operation that doesn't override it (see CKV_OPENAPI_7 for the per-operation equivalent). If `http` is included here, it becomes the default fallback for the entire API surface — every endpoint that omits its own `schemes` override is implicitly declared as reachable over plaintext HTTP. This exposes all request and response data (including auth tokens, cookies, and any sensitive payloads) to network interception, on-path tampering, and downgrade attacks, since clients following the spec are told plaintext is an acceptable way to reach the API.

## How Checkov evaluates this
The check (`GlobalSchemeDefineHTTP`, a document-level `BaseOpenapiCheckV2`):
1. Reads the root-level `schemes` field.
2. If it is missing/empty, the result is `UNKNOWN` — Swagger 2.0 says the default scheme in that case is whatever protocol was used to access the document itself, which Checkov cannot determine statically.
3. If `schemes` is present and contains `"http"`, the check **FAILS**.
4. Otherwise **PASSES**.

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
schemes:
  - http
  - https
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
schemes:
  - https
paths:
  /items:
    get:
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Remove `http` (and `ws`, if unencrypted WebSocket is also declared) from the root-level `schemes` array, keeping only `https`/`wss`.
2. If some legacy consumers still require plaintext access during a migration window, isolate that exception to specific operations via a per-operation `schemes` override (and track it for removal — see CKV_OPENAPI_7) rather than leaving `http` in the global default.
3. Verify at the infrastructure layer (load balancer, API gateway, ingress) that plaintext HTTP requests are redirected to HTTPS or rejected outright, since the OpenAPI document is descriptive, not enforcing.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/GlobalSchemeDefineHTTP.py
