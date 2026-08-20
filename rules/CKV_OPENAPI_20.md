# CKV_OPENAPI_20: Ensure that API keys are not sent over cleartext

## Severity
**HIGH** (score: 8.0/10)

Allowing an apiKey-based security scheme on operations reachable over unencrypted HTTP/WS lets a network attacker intercept the static API key and fully impersonate the caller.

## Summary
No operation that requires an `apiKey`-type security scheme should be reachable over an unencrypted transport (`http`/`ws`), since API keys sent in cleartext are as easily stolen as passwords.

## Applicability
**Checkov framework(s):** `openapi`

- **IaC framework:** OpenAPI (both Swagger 2.0 `securityDefinitions` and OpenAPI 3.x `components.securitySchemes` — this is a "generic" version-agnostic check).
- **Entity:** `paths` (operations using `apiKey`-type schemes), evaluated together with `schemes` (2.0) / `servers` (3.x) and `securityDefinitions`/`components.securitySchemes`.

## Why it matters
API keys function as long-lived bearer credentials — anyone who obtains the key can impersonate the legitimate caller until the key is rotated or revoked. If the API is reachable over plaintext HTTP or unencrypted WebSocket, the key (typically sent in a header, query parameter, or cookie) travels unencrypted across the network and can be captured by anyone with visibility into the traffic path: network sniffers, misconfigured intermediary proxies, shared Wi-Fi, or compromised routers. Unlike short-lived OAuth2 tokens, API keys often have no built-in expiration, so a single capture can grant an attacker long-term, sometimes unlimited, access to the API under the victim's identity.

## How Checkov evaluates this
The check (`ClearTestAPIKey`, a document-level `BaseOpenapiCheck` — works across spec versions):
1. Checks the document's transport declarations first:
   - Swagger 2.0: if `schemes` is present and neither `"http"` nor `"ws"` appears in it, the check **PASSES** immediately (transport is safely restricted to encrypted protocols).
   - OpenAPI 3.x: if `servers` is present and none of the server URLs start with `http://` or `ws://`, the check **PASSES** immediately.
2. If transport isn't safely restricted (or wasn't declared), it looks for `apiKey`-type schemes: `components.securitySchemes` (3.x) or `securityDefinitions` (2.0), filtering down to schemes where `type == "apiKey"`.
3. If no `apiKey` schemes exist, the check **PASSES** (nothing at risk).
4. Otherwise, it scans every operation in `paths`; if an operation's `security` requirement references one of the `apiKey` schemes, the check **FAILS**.
5. If no operation actually uses an `apiKey` scheme, it **PASSES**.

## Non-compliant example
```yaml
openapi: "3.0.0"
info:
  title: Sample API
  version: "1.0"
servers:
  - url: http://api.example.com
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      name: X-API-Key
      in: header
paths:
  /data:
    get:
      security:
        - apiKeyAuth: []
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
servers:
  - url: https://api.example.com
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      name: X-API-Key
      in: header
paths:
  /data:
    get:
      security:
        - apiKeyAuth: []
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Change every `servers` URL (OpenAPI 3.x) or `schemes` entry (Swagger 2.0) to use `https://`/`https` (and `wss` instead of `ws` for WebSocket) — eliminate plaintext transport declarations entirely.
2. Confirm the actual deployed infrastructure (load balancer, ingress, reverse proxy) enforces TLS and redirects or blocks plaintext connections, since the spec alone doesn't enforce transport security.
3. If API keys must remain in use, prefer sending them in headers rather than query strings (query strings are more likely to be logged by proxies/servers), and rotate keys periodically regardless of transport.
4. Consider migrating from static API keys to short-lived, scoped OAuth2 tokens where feasible, reducing the blast radius of any future leak.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/generic/ClearTextAPIKey.py
