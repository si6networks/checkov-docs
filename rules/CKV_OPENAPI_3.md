# CKV_OPENAPI_3: Ensure that security schemes don't allow cleartext credentials over unencrypted channel - version 3.x.y files

## Severity
**HIGH** (score: 7.5/10)

Defining an HTTP Basic security scheme that is actually used by operations permits raw, reversible credentials to be sent over what the spec allows to be an unencrypted channel, exposing them to interception.

## Summary
For OpenAPI 3.x documents, this check fails if any `components.securitySchemes` entry uses HTTP Basic authentication (`type: http`, `scheme: basic`), or if any operation in `paths` declares a `security` requirement at all while such a scheme is (or could be) in play — because Basic auth sends credentials in cleartext (base64, not encryption) unless the transport is guaranteed to be TLS.

## Applicability
**Checkov framework(s):** `openapi`

- **IaC framework:** OpenAPI (version 3.x.y specification files, JSON or YAML).
- **Entity:** `components` (specifically `components.securitySchemes`), evaluated together with `paths`.

## Why it matters
HTTP Basic authentication transmits the username and password Base64-encoded in the `Authorization` header — this is trivially reversible, not encryption. If the scheme is used without an enforced HTTPS-only transport, credentials are exposed to anyone who can observe the traffic: on-path attackers, misconfigured proxies, logging middleware that captures headers, or browser extensions. Because OpenAPI 3 documents do not always pin transport security at the scheme level, declaring `type: http, scheme: basic` is inherently risky in a spec meant to describe how clients should call the API — it invites implementations that send credentials in cleartext, especially if any deployment target or environment omits TLS termination.

## How Checkov evaluates this
The check (`CleartextCredsOverUnencryptedChannel`, a `BaseOpenapiCheckV3` document-level check):
1. Reads `components.securitySchemes`.
2. For each named scheme, if `type == "http"` and `scheme == "basic"`, the check **FAILS** immediately.
3. If no such scheme is found, it then checks every operation under `paths`: for any operation object with a truthy `security` field, the check also **FAILS**.
4. Only if no Basic-auth scheme exists AND no operation declares a `security` requirement does the check **PASS**.

Note the second branch means simply having *any* per-operation `security` requirement (regardless of scheme type) after passing the Basic-auth-scan of `securitySchemes` can also trigger a FAIL in this implementation — in practice this check is strictest when Basic auth (or any operation-level security) is combined without a scheme, so the safest posture is avoiding `type: http, scheme: basic` altogether.

## Non-compliant example
```yaml
openapi: "3.0.0"
info:
  title: Sample API
  version: "1.0"
components:
  securitySchemes:
    basicAuth:
      type: http
      scheme: basic
paths:
  /account:
    get:
      security:
        - basicAuth: []
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
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
paths:
  /account:
    get:
      security:
        - bearerAuth: []
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Replace `type: http, scheme: basic` security schemes with a stronger mechanism: bearer tokens (`type: http, scheme: bearer`), OAuth2, or OpenID Connect.
2. If Basic auth must be retained for legacy reasons, ensure it is only ever served over TLS in every deployment, and document that constraint outside the scheme definition (the OpenAPI spec itself has no way to force TLS-only enforcement on a `http`/`basic` scheme).
3. Review all `paths` operations for `security` requirements and confirm each references a properly encrypted scheme.
4. Consider adding `servers` entries that only use `https://` URLs to reduce ambiguity about the transport.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v3/CleartextOverUnencryptedChannel.py
