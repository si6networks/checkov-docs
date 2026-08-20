# CKV_AWS_50: X-Ray tracing is enabled for Lambda
## Severity
**LOW** (score: 2.0/10)

Disabled X-Ray tracing reduces operational and performance observability for a Lambda function but has no direct confidentiality, integrity, or availability impact on its own.

## Summary
This check ensures Lambda functions have AWS X-Ray active tracing enabled, so invocations can be traced for observability and troubleshooting.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_lambda_function`

## Why it matters
X-Ray tracing provides distributed request tracing across Lambda and other integrated AWS services (API Gateway, DynamoDB, SQS, downstream HTTP calls), which is essential for diagnosing latency issues, understanding request flow through a serverless architecture, and — from a security perspective — reconstructing the path of a request during incident investigation (e.g., tracing an anomalous or malicious invocation chain across services). Without tracing enabled, teams lose critical visibility during an incident: it becomes much harder to determine which downstream calls a compromised or misbehaving function made, correlate a suspicious invocation with its full call graph, or detect unusual latency/error patterns that could indicate an ongoing attack (e.g., a function being used for resource-exhaustion or exfiltration attempts). This is primarily a reliability/observability control with secondary security-incident-response value.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` against `aws_lambda_function`, inspecting `tracing_config[0].mode`:
- **PASS** if `tracing_config { mode = "Active" }` or `mode = "PassThrough"` (both accepted values).
- **FAIL** if the `tracing_config` block is absent, or `mode` is set to something else (tracing disabled by default when unset).

## Non-compliant example
```hcl
resource "aws_lambda_function" "example" {
  function_name = "example-fn"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "function.zip"
  role          = aws_iam_role.lambda_exec.arn
  # tracing_config not set -> X-Ray tracing disabled
}
```

## Remediated example
```hcl
resource "aws_lambda_function" "example" {
  function_name = "example-fn"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "function.zip"
  role          = aws_iam_role.lambda_exec.arn

  tracing_config {
    mode = "Active"
  }
}
```

## Remediation steps
1. Add a `tracing_config { mode = "Active" }` block to the `aws_lambda_function` resource (use `"Active"` to always sample, or `"PassThrough"` to only trace when the incoming request is already being traced by an upstream service like API Gateway).
2. Grant the function's execution role the AWS-managed `AWSXRayDaemonWriteAccess` policy (or equivalent minimal `xray:PutTraceSegments`/`xray:PutTelemetryRecords` permissions) — tracing will silently fail to record without this.
3. If using a language runtime with the X-Ray SDK, instrument outbound calls (HTTP, AWS SDK clients) within the function code to get full downstream visibility, not just the Lambda invocation segment itself.
4. Be aware of X-Ray's per-trace cost at high invocation volume; use sampling rules to control cost if `Active` tracing is applied broadly.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LambdaXrayEnabled.py)
- [AWS Lambda X-Ray tracing documentation](https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html)
