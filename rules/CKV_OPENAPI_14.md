# CKV_OPENAPI_14: Ensure that operation objects do not use 'implicit' flow, which is deprecated - version 2.0 files

## Severity
**MEDIUM** (score: 5.0/10)

Allowing the deprecated OAuth2 implicit flow on an individual operation exposes access tokens via the URL fragment, making them susceptible to leakage through logs, history, or referrer headers.

## Summary
For Swagger 2.0 documents, no operation's `security` requirement should resolve (via `securityDefinitions`) to an OAuth2 scheme configured with `flow: implicit` — this checks usage at the operation level, complementing CKV_OPENAPI_12 which checks the scheme definitions.

## Applicability
- **IaC framework:** OpenAPI (Swagger 2.0 specification files, JSON or YAML).
- **Entity:** `paths` (each operation's `security` field, resolved against `securityDefinitions`).

## Why it matters
Even if a scheme with `flow: implicit` is only referenced by a subset of operations rather than defined broadly, using it anywhere still exposes those specific endpoints to the Implicit grant's weaknesses: tokens delivered via URL fragment are susceptible to leakage through browser history, `Referer` headers, and JavaScript-based exfiltration, and there is no refresh-token mechanism, encouraging longer-lived (riskier) access tokens or frequent re-authentication prompts that train users to accept redirects blindly (a phishing vector). Checking per-operation usage catches cases where the deprecated flow definition exists in the spec for legacy reasons but is only supposed to be inert — this check flags every place it is actually wired up to a live operation.

## How Checkov evaluates this
The check (`OperationObjectImplicitFlow`, a document-level `BaseOpenapiCheckV2`):
1. Reads `paths` and `securityDefinitions`.
2. Iterates every operation under every path.
3. For each operation's `security` list, and each scheme key referenced within each requirement, resolves the scheme in `securityDefinitions`.
4. If that scheme's `flow == "implicit"`, the check **FAILS**.
5. Non-dict path/operation/security-requirement structures yield `UNKNOWN`.
6. Otherwise **PASSES**.

## Non-compliant example
```yaml
swagger: "2.0"
info:
  title: Sample API
  version: "1.0"
securityDefinitions:
  oauth2Implicit:
    type: oauth2
    flow: implicit
    authorizationUrl: https://auth.example.com/authorize
    scopes:
      read: Read access
paths:
  /dashboard:
    get:
      security:
        - oauth2Implicit:
            - read
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
securityDefinitions:
  oauth2Code:
    type: oauth2
    flow: accessCode
    authorizationUrl: https://auth.example.com/authorize
    tokenUrl: https://auth.example.com/token
    scopes:
      read: Read access
paths:
  /dashboard:
    get:
      security:
        - oauth2Code:
            - read
      responses:
        "200":
          description: OK
```

## Remediation steps
1. Identify every operation whose `security` requirement resolves to a `flow: implicit` scheme.
2. Repoint those operations to a scheme using `flow: accessCode` (Authorization Code) once that scheme is defined (see CKV_OPENAPI_12 remediation).
3. Update client applications calling those specific operations to perform the code-exchange flow.
4. Remove the now-unused implicit-flow scheme from `securityDefinitions` if no operation references it anymore.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/openapi/checks/resource/v2/OperationObjectImplicitFlow.py
- OAuth 2.0 Security Best Current Practice (recommends against Implicit): https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
