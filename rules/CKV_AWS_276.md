# CKV_AWS_276: Ensure Data Trace is not enabled in API Gateway Method Settings
## Severity
**LOW** (score: 2.0/10)

Enabling full request/response data tracing can leak sensitive payload data (e.g. tokens, PII) into CloudWatch Logs, but exploitation requires separate access to those logs, so this is a data-exposure hygiene issue rather than a direct compromise path.

## Summary
This check fails when an API Gateway stage's method settings have `data_trace_enabled` set to `true`, because full request/response data tracing in CloudWatch Logs can leak sensitive payload data.

## Applicability
- **Framework:** Terraform
- **Resource:** `aws_api_gateway_method_settings`

## Why it matters
API Gateway's "data trace" (`dataTraceEnabled` in the API, exposed via CloudWatch full request/response logging) writes the complete content of every request and response — including headers, query strings, and body — to CloudWatch Logs. If the API handles anything sensitive (auth tokens, PII, credit card numbers, session identifiers passed in headers or bodies), this results in that sensitive data being persisted in plaintext log storage that may have broader IAM read access, longer retention, and different encryption/monitoring posture than the primary data store. It also increases the blast radius of a CloudWatch Logs compromise and can create compliance violations (e.g., PCI-DSS, HIPAA) by duplicating regulated data into an uncontrolled sink. Data trace is intended strictly as a temporary debugging aid, not something that should be left on in any persistent configuration, and especially not in production.

## How Checkov evaluates this
Checkov uses `BaseResourceNegativeValueCheck` and inspects the Terraform attribute path `settings/[0]/data_trace_enabled` on `aws_api_gateway_method_settings`. It fails (FAIL) if that value is present and equal to `True`. If the attribute is absent or `false`, the check passes.

## Non-compliant example
```hcl
resource "aws_api_gateway_method_settings" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    logging_level      = "INFO"
    data_trace_enabled = true
  }
}
```

## Remediated example
```hcl
resource "aws_api_gateway_method_settings" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    logging_level      = "INFO"
    data_trace_enabled = false
  }
}
```

## Remediation steps
1. Set `data_trace_enabled = false` (or remove the attribute, since `false` is the default) in every `aws_api_gateway_method_settings` block.
2. If you need to debug a specific issue, enable data trace temporarily via the console/CLI on a non-production stage, capture what you need, and turn it back off — do not commit it to IaC.
3. Rely on `metrics_enabled` and `logging_level = "INFO"`/`"ERROR"` for ongoing operational visibility instead of full data tracing.
4. If detailed payload inspection is required long-term, route traffic through a component with proper redaction/masking (e.g., a WAF or a custom Lambda authorizer with scrubbed logging) rather than raw API Gateway data trace.
5. Audit any CloudWatch Log Groups that may already contain traced payload data and consider deleting/redacting historical log streams and shortening retention.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayMethodSettingsDataTrace.py
- AWS docs: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-cloudwatch-logs.html
