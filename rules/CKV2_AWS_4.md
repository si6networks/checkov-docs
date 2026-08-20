# CKV2_AWS_4: Ensure API Gateway stage have logging level defined as appropriate
## Severity
**LOW** (score: 2.0/10)

Missing or insufficient API Gateway logging limits the ability to detect and investigate abuse or attacks against the API, a monitoring/detective-control gap rather than a direct vulnerability.

## Summary
This check ensures that every `aws_api_gateway_stage` has an associated `aws_api_gateway_method_settings` resource that sets a valid `logging_level` (`ERROR` or `INFO`) and enables `metrics_enabled`, so execution logging and CloudWatch metrics are actually turned on for the stage.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_api_gateway_stage` (connected `aws_api_gateway_method_settings`)
- **Category:** Logging

## Why it matters
Without execution logging enabled on an API Gateway stage, requests hitting the API leave no record of what happened at the gateway layer: which methods were invoked, what status codes were returned, whether authorization/authentication failed or succeeded, and any integration errors between API Gateway and its backend (Lambda, HTTP endpoint, etc.). This is a significant gap for incident response — if an attacker is probing the API for vulnerable endpoints, attempting to bypass authorization, or triggering integration errors to enumerate backend behavior, there is no CloudWatch log trail to detect or investigate it after the fact. `metrics_enabled` similarly controls whether CloudWatch metrics (4XX/5XX error rates, latency, request counts) are published, which are commonly used both for operational alerting and as an early-warning signal for attack patterns (e.g., a spike in 401/403 responses indicating brute-force or scanning activity). Leaving both off means the API operates with no observability into either its correctness or its abuse.

## How Checkov evaluates this
This is a graph check (`APIGWLoggingLevelsDefinedProperly.json`). It requires ALL of:
1. A graph connection exists from the `aws_api_gateway_stage` to an `aws_api_gateway_method_settings` resource.
2. That method settings resource's `settings.logging_level` attribute equals either `ERROR` or `INFO`.
3. That method settings resource's `settings.metrics_enabled` attribute equals `true`.
4. The resource being evaluated is filtered as `aws_api_gateway_stage`.

A stage with no connected `aws_api_gateway_method_settings` at all, or one with `logging_level = "OFF"` (or unset, which defaults to `OFF`), or with `metrics_enabled = false`/unset, fails the check.

## Non-compliant example
```hcl
resource "aws_api_gateway_stage" "prod" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deploy.id
}
# No aws_api_gateway_method_settings — logging and metrics remain off
```

## Remediated example
```hcl
resource "aws_api_gateway_stage" "prod" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deploy.id
}

resource "aws_api_gateway_method_settings" "prod_settings" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"

  settings {
    logging_level   = "ERROR"
    metrics_enabled = true
  }
}
```

## Remediation steps
1. Add an `aws_api_gateway_method_settings` resource for the stage, using `method_path = "*/*"` to apply settings to all methods/resources in the stage (or scope it to specific methods if you need per-method granularity).
2. Set `settings.logging_level` to `ERROR` (log only 4XX/5XX and integration errors — lower volume) or `INFO` (log all requests — more verbose, useful for detailed auditing/debugging) depending on your logging volume and compliance needs.
3. Set `settings.metrics_enabled = true` to publish CloudWatch metrics for the stage.
4. Ensure the API Gateway account-level CloudWatch Logs role is configured (`aws_api_gateway_account` with a `cloudwatch_role_arn`) — without this account-level IAM role granting API Gateway permission to write to CloudWatch Logs, enabling `logging_level` on the stage will not actually produce logs.
5. Consider also enabling `data_trace_enabled` for non-production stages only (verbose request/response body logging) — avoid enabling it in production due to potential sensitive-data exposure in logs and higher log volume/cost.
6. Set an appropriate CloudWatch Logs retention period on the destination log group to control cost while meeting audit requirements.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/APIGWLoggingLevelsDefinedProperly.json)
- [AWS API Gateway logging documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html)
