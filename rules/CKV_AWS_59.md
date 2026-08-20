# CKV_AWS_59: Ensure there is no open access to back-end resources through API
## Severity
**CRITICAL** (score: 9.5/10)

An API Gateway method with no authorization exposes the backend integration directly to the public internet with no authentication, allowing anyone to invoke potentially sensitive or state-changing operations.

## Summary
This check fails when an API Gateway method (other than `OPTIONS`) has no authorization configured (`AuthorizationType: NONE`) and also does not require an API key, meaning the endpoint is fully open to unauthenticated, unmetered public callers.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::ApiGateway::Method`, properties `HttpMethod`, `AuthorizationType`, `ApiKeyRequired`.
- **Terraform**: `aws_api_gateway_method` resource, attributes `http_method`, `authorization`, `api_key_required`.

## Why it matters
API Gateway methods sit directly in front of backend integrations — Lambda functions, HTTP backends, or AWS service integrations — and are often the literal front door to sensitive business logic or data. If a method has no authorizer (IAM, Cognito, Lambda authorizer) and no API key requirement, absolutely anyone on the internet can invoke it with no rate limiting, no identity, and no audit trail tying requests to a caller. This is a common root cause of API abuse: credential-stuffing against a backend, unmetered access leading to cost/DoS exposure, or outright unauthorized access to data/actions the endpoint exposes. The check correctly exempts `OPTIONS` methods since those are CORS preflight requests that inherently carry no business logic and are supposed to be publicly reachable.

## How Checkov evaluates this
**CloudFormation**: for each `AWS::ApiGateway::Method`, if `HttpMethod != "OPTIONS"` AND `AuthorizationType == "NONE"` AND (`ApiKeyRequired` is absent OR `false`) → FAILS. Otherwise PASSES.

**Terraform**: FAILS when `http_method != "OPTIONS"` AND (`authorization` is absent OR equals `"NONE"`) AND (`api_key_required` is absent OR `false`). PASSES otherwise — i.e., PASSES if the method uses any authorization type other than `NONE` (e.g., `AWS_IAM`, `CUSTOM`, `COGNITO_USER_POOLS`) or if it requires an API key.

Note that requiring only an API key is sufficient to pass this specific check, even though an API key alone is a weak, non-cryptographic form of access control (it does not by itself provide strong authentication) — for genuinely sensitive backends, prefer IAM/Cognito/Lambda authorizers over API-key-only gating.

## Non-compliant example
```hcl
resource "aws_api_gateway_method" "get_orders" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.orders.id
  http_method   = "GET"
  authorization = "NONE"      # non-compliant
  # api_key_required not set -> defaults to false
}
```

## Remediated example
```hcl
resource "aws_api_gateway_method" "get_orders" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.orders.id
  http_method   = "GET"
  authorization = "AWS_IAM"   # fixed: require SigV4-signed IAM auth
}
```

## Remediation steps
1. For each non-`OPTIONS` method, set `authorization` to `AWS_IAM`, `COGNITO_USER_POOLS`, or `CUSTOM` (Lambda authorizer) as appropriate for your client population.
2. If the endpoint is meant to be reachable by internal services only, prefer `AWS_IAM` combined with a resource policy or VPC endpoint restriction.
3. If a public API is intentional but usage should be tracked/throttled, set `api_key_required = true` and enforce usage plans — but understand this is not strong authentication, only identification/metering.
4. Leave `OPTIONS` methods with `authorization = "NONE"` — this is expected and required for CORS preflight.
5. Re-deploy the API stage after changing method authorization (a new deployment is required for the change to take effect for live traffic).

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/APIGatewayAuthorization.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayAuthorization.py)
- [AWS: Control access to a REST API using IAM permissions](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-using-iam-policies-to-invoke-api.html)
