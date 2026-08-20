# CKV_AWS_309: Ensure API GatewayV2 routes specify an authorization type

## Severity
**MEDIUM** (score: 5.0/10)

A missing authorization type on an API GatewayV2 route means the route can be invoked by any unauthenticated caller, directly exposing backend functionality without access control.

## Summary
This check ensures that every AWS API Gateway v2 (HTTP/WebSocket API) route explicitly declares an `authorization_type`, preventing routes from being reachable with no access control.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_apigatewayv2_route`

## Why it matters
API Gateway v2 routes without an explicit authorization type default to `NONE`, meaning any client on the internet can invoke the associated integration (Lambda function, HTTP backend, etc.) without any authentication or authorization check. This is a common cause of unintentionally public APIs — a developer forgets to wire up an authorizer and the route silently accepts unauthenticated traffic. Requiring an explicit type forces a conscious decision about how the route is protected (IAM signing, a JWT authorizer, or a custom Lambda authorizer), aligning with NIST 800-53 controls for access enforcement (AC-3) and baseline configuration management (CM-2).

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` that inspects the `authorization_type` attribute on `aws_apigatewayv2_route`:
- **PASS** if `authorization_type` is set to one of `"AWS_IAM"`, `"CUSTOM"`, or `"JWT"`.
- **FAIL** if the attribute is absent, or set to any other value (including the implicit/explicit `"NONE"`).

## Non-compliant example
```hcl
resource "aws_apigatewayv2_api" "example" {
  name          = "example-http-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_route" "example" {
  api_id    = aws_apigatewayv2_api.example.id
  route_key = "GET /items"
  target    = "integrations/${aws_apigatewayv2_integration.example.id}"
  # No authorization_type set -> defaults to NONE, publicly invocable
}
```

## Remediated example
```hcl
resource "aws_apigatewayv2_api" "example" {
  name          = "example-http-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id           = aws_apigatewayv2_api.example.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "jwt-authorizer"

  jwt_configuration {
    audience = ["https://api.example.com"]
    issuer   = "https://auth.example.com"
  }
}

resource "aws_apigatewayv2_route" "example" {
  api_id             = aws_apigatewayv2_api.example.id
  route_key          = "GET /items"
  target             = "integrations/${aws_apigatewayv2_integration.example.id}"
  authorization_type = "JWT"                      # explicit authorization
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}
```

## Remediation steps
1. Identify every `aws_apigatewayv2_route` resource in the configuration.
2. Decide the correct authorization model for the route: `AWS_IAM` for SigV4-signed internal/service-to-service calls, `JWT` for OIDC/OAuth2-based user authentication (HTTP APIs only), or `CUSTOM` for a Lambda authorizer.
3. Set `authorization_type` accordingly, and if using `JWT` or `CUSTOM`, also create and attach the matching `aws_apigatewayv2_authorizer` resource via `authorizer_id`.
4. If a route is genuinely meant to be public (e.g., a health-check endpoint), set `authorization_type = "NONE"` explicitly and consider suppressing the finding with a documented Checkov skip comment rather than leaving it unset.
5. Re-run `terraform plan` — attaching an authorizer to an existing route does not require resource replacement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayV2RouteDefinesAuthorizationType.py
- AWS docs: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-access-control.html
