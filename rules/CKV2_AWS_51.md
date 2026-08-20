# CKV2_AWS_51: Ensure AWS API Gateway endpoints uses client certificate authentication
## Severity
**MEDIUM** (score: 5.0/10)

Omitting client certificate authentication on API Gateway removes an additional mutual-TLS authentication layer, but the API can still rely on other authorizers, making this a defense-in-depth gap rather than a fully open endpoint.

## Summary
This check fails when an API Gateway (REST or HTTP, but not WebSocket) stage does not have a `client_certificate_id` configured, meaning API Gateway does not present a certificate to authenticate itself to backend integrations, and backends have no way to verify that requests actually originated from your API Gateway rather than a spoofed source.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_api_gateway_stage` (REST APIs), `aws_apigatewayv2_api`, `aws_apigatewayv2_stage` (HTTP APIs — WebSocket APIs are exempted)

## Why it matters
Client certificate authentication lets API Gateway present a certificate to your backend/origin server when making the outbound call, and lets the backend validate that certificate before trusting the request. Without it, if your backend is reachable by any path other than strictly through API Gateway (e.g., a load balancer with a public or otherwise-reachable listener, a VPC that isn't fully locked down to only the API Gateway's IP ranges), there is no cryptographic way for the backend to distinguish a legitimate request routed through API Gateway (with its associated throttling, auth, WAF, and logging) from a forged request sent directly to the backend that bypasses all of that. This matters most when the backend is designed to trust "anything coming from API Gateway" implicitly — without client cert validation, that trust boundary is only as strong as network reachability, which is a much weaker guarantee than cryptographic proof of origin.

## How Checkov evaluates this
This is a graph-based JSON policy with three `or` branches:
1. **PASS** if `aws_api_gateway_stage.client_certificate_id` exists (REST API stage has a client cert configured).
2. **PASS** if `aws_apigatewayv2_stage.client_certificate_id` exists (note: this attribute doesn't actually exist on `aws_apigatewayv2_stage` in the AWS provider schema for HTTP/WebSocket APIs — this branch effectively never matches for v2, so v2 stages rely on branch 3).
3. **PASS** if the stage is an `aws_apigatewayv2_stage` that either has no connected `aws_apigatewayv2_api` at all, OR is connected to one whose `protocol_type` is **not** `WEBSOCKET` (i.e., WebSocket APIs are exempted from this requirement entirely).
- **FAIL** occurs for a REST API stage (`aws_api_gateway_stage`) with no `client_certificate_id`, since that's the only resource type where this attribute meaningfully applies and is checked.

## Non-compliant example
```hcl
resource "aws_api_gateway_rest_api" "api" {
  name = "example-api"
}

resource "aws_api_gateway_deployment" "api" {
  rest_api_id = aws_api_gateway_rest_api.api.id
}

resource "aws_api_gateway_stage" "bad" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.api.id
  # no client_certificate_id
}
```

## Remediated example
```hcl
resource "aws_api_gateway_client_certificate" "api" {
  description = "Client cert for prod stage backend auth"
}

resource "aws_api_gateway_rest_api" "api" {
  name = "example-api"
}

resource "aws_api_gateway_deployment" "api" {
  rest_api_id = aws_api_gateway_rest_api.api.id
}

resource "aws_api_gateway_stage" "good" {
  stage_name           = "prod"
  rest_api_id           = aws_api_gateway_rest_api.api.id
  deployment_id         = aws_api_gateway_deployment.api.id
  client_certificate_id = aws_api_gateway_client_certificate.api.id
}
```

## Remediation steps
1. Create an `aws_api_gateway_client_certificate` resource.
2. Reference its ID via `client_certificate_id` on the `aws_api_gateway_stage`.
3. Configure the backend/origin server (e.g. an ALB target, on-prem endpoint, or HTTP integration behind the stage) to require and validate this certificate — this typically means installing API Gateway's public certificate (retrievable via `GetClientCertificate`) as a trusted CA/cert on the backend's TLS termination point.
4. Rotate the client certificate before its expiration (client certificates are valid for a fixed period and don't auto-renew) — track the `expiration_date` attribute and set a reminder well ahead of it, since an expired cert will cause backend calls to fail if the backend is strictly enforcing validation.
5. This check does not apply to `WEBSOCKET`-protocol HTTP APIs; if your `aws_apigatewayv2_api` has `protocol_type = "HTTP"`, note that `client_certificate_id` is not actually a supported attribute on `aws_apigatewayv2_stage` in the Terraform AWS provider — for HTTP APIs, mutual TLS is instead configured via a custom domain's `mutual_tls_authentication` block on `aws_apigatewayv2_domain_name`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/APIGatewayEndpointsUsesCertificateForAuthentication.json
- AWS docs: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-mutual-tls.html
