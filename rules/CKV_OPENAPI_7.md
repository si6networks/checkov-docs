# CKV_OPENAPI_7: Ensure that the path scheme does not support unencrypted HTTP connection where all transmissions are open to interception - version 2.0 files

## Severity
**HIGH** (score: 7.5/10)

Allowing 'http' in an operation's own schemes exposes that endpoint's traffic, including any credentials or tokens sent with the request, to network interception.

## Summary
For Swagger 2.0 documents, no individual operation should declare `http` in its per-operation `schemes` list, since this would allow that specific endpoint to be reached over an unencrypted connection.

## Applicability
- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `security` / `paths` (operation-level `schemes` field).

## Why it matters
Swagger 2.0 lets individual operations override the document's global `schemes` to specify which transport protocols (`http`, `https`, `ws`, `wss`) they support. If any operation explicitly lists `http`, clients are permitted (per the spec) to call that endpoint over plaintext HTTP. All request/response data — including any credentials, tokens, cookies, or sensitive payloads — travels unencrypted and is exposed to network eavesdroppers, on-path proxies, and anyone sharing the same network segment (e.g., public Wi-Fi, compromised routers). This is a straightforward information-disclosure and credential-theft risk, and it undermines the confidentiality guarantees users assume when interacting with a secured API.

## How Checkov evaluates this
The check (`PathSchemeDefineHTTP`, a document-level `BaseOpenapiCheckV2`):
1. Reads `paths`; if missing/empty or not a dict, the result is `UNKNOWN` (nothing to check).
2. Iterates every operation under every path.
3. For each operation, reads its `schemes` field; if it is present and contains `"http"`, the check **FAILS**.
4. If an operation has no `schemes` field at all, the spec says the default is whatever scheme was used to access the Swagger document itself — Checkov treats this as not evaluable for this specific check and continues.
5. Passes if no operation explicitly lists `http` in its `schemes`.

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
schemes:
  - https
paths:
  /legacy-upload:
    post:
      schemes:
        - http
        - https
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
  /legacy-upload:
    post:
      schemes:
        - https
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Search all operations for a `schemes` field and remove `http` (and `ws`, if unencrypted WebSocket is also present) from the list, keeping only `https`/`wss`.
2. If an operation has no legitimate need to override the global scheme, simply delete the operation-level `schemes` field entirely so it inherits the (presumably HTTPS-only) global setting.
3. Confirm the global `schemes` field (document root) also excludes `http` — this specific check only covers operation-level overrides; global scheme enforcement is a related but separate concern (see CKV_OPENAPI_18).
4. At the infrastructure layer, ensure any load balancer/ingress actually terminates or redirects plaintext HTTP to HTTPS, since the spec alone is documentation, not enforcement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/PathSchemeDefineHTTP.py
