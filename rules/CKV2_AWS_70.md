# CKV2_AWS_70: Ensure API gateway method has authorization or API key set

## Severity
**MEDIUM** (score: 5.0/10)

An API Gateway method with no authorization and no API key (and no compensating private/deny policy) allows any unauthenticated caller to invoke the backend, a broad exposure of what is meant to be a controlled-access API.

## Summary
This check flags `aws_api_gateway_method` resources that use the `OPTIONS` HTTP method with `authorization = "NONE"` and no `api_key_required`, unless the parent REST API is restricted to `PRIVATE` endpoint access or is protected by a resource policy that denies/restricts unauthenticated `execute-api:Invoke` calls.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_api_gateway_method` (evaluation also inspects the connected `aws_api_gateway_rest_api` and, optionally, `aws_api_gateway_rest_api_policy`)

## Why it matters
API Gateway methods with `authorization = "NONE"` and no API key are callable by anyone who can reach the endpoint, with no verification of caller identity. While `OPTIONS` methods (used for CORS preflight) are commonly left unauthenticated by convention since they typically don't execute business logic, this check treats that as the specific pattern worth verifying isn't masking a broader gap: if the REST API is `PUBLIC` (internet-facing, the default) and has no resource policy restricting invocation, an open `OPTIONS` method combined with a public API surface signals the API's authorization posture may not have been deliberately reviewed at all, since the safe patterns are: (a) the API is `PRIVATE` (VPC-endpoint only, unreachable from the public internet regardless of per-method auth), or (b) a resource policy actively denies unauthenticated `execute-api:Invoke` calls at the API Gateway layer. Absent either, an inadvertently unauthenticated method configuration is one of the more common causes of exposed APIs leaking data or accepting unauthenticated write operations.

## How Checkov evaluates this
This is a **Python resource check** (`checkov/terraform/checks/resource/aws/APIGatewayMethodWOAuth.py`), with graph-traversal logic in `scan_resource_conf`:
1. **Immediate PASS conditions** (evaluated first, no further graph lookups needed):
   - `authorization` is set to anything other than `"NONE"`, OR
   - `api_key_required` is explicitly truthy, OR
   - `http_method` is anything other than `"OPTIONS"`.
2. **If none of those hold** (i.e., it's an `OPTIONS` method with `authorization = "NONE"` and no API key), the check locates the connected `aws_api_gateway_rest_api` node in the graph and:
   - **PASSES** if the REST API's `endpoint_configuration.types` is exactly `["PRIVATE"]`.
   - Otherwise, if the REST API has a `policy` attribute, calls `_is_policy_secure()` on it (or, if the policy is attached via a separate `aws_api_gateway_rest_api_policy` resource, on that resource's policy instead).
3. `_is_policy_secure()` inspects the policy's `Statement` (or Terraform's `statement` block syntax) for `execute-api:Invoke`/`execute-api:*`/`*` actions:
   - **PASSES** if any statement has `Effect: Deny` with `Principal: "*"` covering that action.
   - **FAILS** if any statement has `Effect: Allow` with `Principal: "*"`, no `Condition`, and covers that action (i.e., truly open invocation with no source restriction).
   - If no `aws_api_gateway_rest_api` node is found and no policy exists, the check returns **UNKNOWN**.

## Non-compliant example
```hcl
resource "aws_api_gateway_rest_api" "api" {
  name = "public-api"
  # No endpoint_configuration -> defaults to EDGE (public)
  # No policy -> no invocation restriction
}

resource "aws_api_gateway_resource" "widgets" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "widgets"
}

resource "aws_api_gateway_method" "options" {
  rest_api_id      = aws_api_gateway_rest_api.api.id
  resource_id      = aws_api_gateway_resource.widgets.id
  http_method      = "OPTIONS"
  authorization    = "NONE"      # unauthenticated
  api_key_required = false       # no API key
  # Public API, no resource policy restriction -> FAILS
}
```

## Remediated example
```hcl
resource "aws_api_gateway_rest_api" "api" {
  name = "public-api"

  endpoint_configuration {
    types = ["PRIVATE"]          # restricts API to VPC endpoint access
  }
}

resource "aws_api_gateway_resource" "widgets" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "widgets"
}

resource "aws_api_gateway_method" "options" {
  rest_api_id      = aws_api_gateway_rest_api.api.id
  resource_id      = aws_api_gateway_resource.widgets.id
  http_method      = "OPTIONS"
  authorization    = "NONE"
  api_key_required = false
  # PRIVATE endpoint type now satisfies the check
}
```

## Remediation steps
1. If the API should truly be private, set `endpoint_configuration { types = ["PRIVATE"] }` on the `aws_api_gateway_rest_api` and attach a resource policy scoping access to your VPC endpoint(s).
2. If the API must be public, attach an `aws_api_gateway_rest_api_policy` (or inline `policy`) that scopes `execute-api:Invoke` with conditions (e.g., `aws:SourceIp`, `aws:SourceVpce`) rather than an unconditional `Allow *`.
3. For non-`OPTIONS` methods that handle real business logic, prefer `authorization = "AWS_IAM"`, `"COGNITO_USER_POOLS"`, or a Lambda authorizer (`"CUSTOM"`) over `"NONE"`, and/or require an API key with usage plans and throttling.
4. Leaving `OPTIONS` unauthenticated is conventional for CORS preflight and generally low-risk on its own — the real fix in most flagged cases is adding the endpoint-type restriction or resource policy at the REST API level, not adding auth to the `OPTIONS` method itself.
5. Re-run `terraform plan` after adding an `aws_api_gateway_rest_api_policy` — API Gateway resource policies require the API to be redeployed (a new `aws_api_gateway_deployment`) to take effect.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayMethodWOAuth.py
- AWS docs: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-resource-policies.html
