# CKV2_AWS_53: Ensure AWS API gateway request is validated
## Severity
**MEDIUM** (score: 5.0/10)

Without request validation, API Gateway forwards malformed or unexpected parameters/bodies to backend integrations, increasing the risk of injection or logic errors being exploited downstream.

## Summary
This check fails when an `aws_api_gateway_method` resource has no `request_validator_id` set, meaning API Gateway performs no built-in validation of incoming request parameters/body before passing the request through to the backend integration.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_api_gateway_method`

## Why it matters
Without request validation configured at the API Gateway layer, every malformed, incomplete, or malicious request is passed straight through to the backend (Lambda, HTTP integration, etc.), which must then defend itself against bad input entirely on its own. This increases the attack surface for injection-style attacks and application-layer bugs (missing required headers/query parameters causing unhandled exceptions, oversized or malformed JSON bodies triggering parser vulnerabilities or resource exhaustion, and generally more surface area for business-logic errors caused by unexpected input shapes). Validating request parameters and body schema at the gateway is a cheap, centralized control that rejects obviously-invalid requests (HTTP 400) before they ever consume backend compute, log volume, or downstream API quota — reducing both the blast radius of malformed/malicious traffic and unnecessary invocations of billed backend resources like Lambda.

## How Checkov evaluates this
This is a graph-based JSON policy checking a single attribute:
- **Attribute checked:** `request_validator_id` on `aws_api_gateway_method`
- **Operator:** `exists`
- **PASS** if the method has a `request_validator_id` referencing an `aws_api_gateway_request_validator`.
- **FAIL** if the attribute is absent, meaning no validator (of any kind — params-only, body-only, or both) is attached to that method.
- Note: the check only confirms a validator is *attached*; it does not verify the validator actually validates both body and parameters (`validate_request_body` / `validate_request_parameters`), nor that a corresponding request `model`/schema is defined for the method.

## Non-compliant example
```hcl
resource "aws_api_gateway_rest_api" "api" {
  name = "example-api"
}

resource "aws_api_gateway_resource" "items" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "items"
}

resource "aws_api_gateway_method" "bad" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.items.id
  http_method   = "POST"
  authorization = "NONE"
  # no request_validator_id
}
```

## Remediated example
```hcl
resource "aws_api_gateway_rest_api" "api" {
  name = "example-api"
}

resource "aws_api_gateway_resource" "items" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "items"
}

resource "aws_api_gateway_request_validator" "body_and_params" {
  name                        = "validate-body-and-params"
  rest_api_id                 = aws_api_gateway_rest_api.api.id
  validate_request_body       = true
  validate_request_parameters = true
}

resource "aws_api_gateway_model" "item" {
  rest_api_id  = aws_api_gateway_rest_api.api.id
  name         = "Item"
  content_type = "application/json"

  schema = jsonencode({
    "$schema" = "http://json-schema.org/draft-04/schema#"
    type      = "object"
    required  = ["name"]
    properties = {
      name = { type = "string" }
    }
  })
}

resource "aws_api_gateway_method" "good" {
  rest_api_id          = aws_api_gateway_rest_api.api.id
  resource_id           = aws_api_gateway_resource.items.id
  http_method            = "POST"
  authorization          = "NONE"
  request_validator_id   = aws_api_gateway_request_validator.body_and_params.id

  request_models = {
    "application/json" = aws_api_gateway_model.item.name
  }
}
```

## Remediation steps
1. Create an `aws_api_gateway_request_validator` for the REST API, choosing `validate_request_body`, `validate_request_parameters`, or both depending on the method's needs.
2. Reference it via `request_validator_id` on each `aws_api_gateway_method`.
3. For body validation to actually enforce a schema, also define an `aws_api_gateway_model` with a JSON Schema and attach it via `request_models` on the method.
4. For parameter validation, mark required parameters via `request_parameters = { "method.request.querystring.foo" = true }` on the method.
5. Test with intentionally malformed requests (missing required field, wrong type) to confirm API Gateway returns `400 Bad Request` before the integration is invoked, rather than passing through to the backend.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/APIGatewayRequestParameterValidationEnabled.json
- AWS docs: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html
