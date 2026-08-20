# CKV_AWS_115: Ensure that AWS Lambda function is configured for function-level concurrent execution limit

## Severity
**LOW** (score: 2.0/10)

Missing a reserved concurrency limit on a Lambda function is primarily an availability concern (risk of runaway invocation exhausting account concurrency and starving other functions), not a confidentiality or access-control issue.

## Summary
Fails when a Lambda function does not set a reserved/limited concurrent execution count, leaving it able to consume unbounded concurrency from the account's shared pool.

## Applicability
- **Terraform**: `aws_lambda_function` resource.
- **CloudFormation/SAM**: `AWS::Lambda::Function`, `AWS::Serverless::Function`.

## Why it matters
By default, a Lambda function can scale up to the account's regional concurrency limit (a shared pool across all functions in the account/region). Without a per-function reserved concurrency limit:
- **Availability/"noisy neighbor" risk**: A single function experiencing a traffic spike, retry storm, or being targeted by an attacker (e.g. a public API endpoint invoking it) can consume the entire account's available concurrency, starving every other Lambda function in the account/region — a form of self-inflicted denial of service.
- **Cost risk**: Unbounded concurrency on a function with an expensive downstream dependency (e.g. a database) can cause runaway costs or overwhelm that downstream dependency (connection exhaustion on an RDS instance, for example).
- **Blast radius control**: Setting a reserved concurrency limit is a defensive control that caps how much damage a single misbehaving or compromised function can do, independent of what triggered the surge.

Note: Checkov's Terraform check treats a reserved concurrency value of `-1` (Terraform's way of representing "use unreserved/unlimited account concurrency") as a specific forbidden value, and treats a missing attribute as a failure too — i.e., some explicit reserved concurrency value must be set.

## How Checkov evaluates this
- **Terraform**: Inspects `reserved_concurrent_executions`. If the attribute is missing, the result defaults to `FAILED` (`missing_attribute_result=CheckResult.FAILED`). If present, the check fails specifically when the value is the interpolated string `"${-1}"` (Terraform's internal representation of `-1`, meaning "no limit set" / unreserved).
- **CloudFormation/SAM**: Inspects `Properties/ReservedConcurrentExecutions`; passes if any value (`ANY_VALUE`) is present, fails if the property is absent.

## Non-compliant example
```hcl
resource "aws_lambda_function" "bad" {
  function_name = "process-orders"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "function.zip"
  # reserved_concurrent_executions not set -> defaults to unreserved/-1
}
```

## Remediated example
```hcl
resource "aws_lambda_function" "good" {
  function_name                 = "process-orders"
  role                           = aws_iam_role.lambda_exec.arn
  handler                        = "index.handler"
  runtime                        = "python3.12"
  filename                       = "function.zip"
  reserved_concurrent_executions = 10
}
```

## Remediation steps
1. Determine an appropriate concurrency ceiling based on expected peak load, downstream dependency capacity (e.g. DB max connections / expected concurrent Lambda invocations), and desired isolation from other functions.
2. Set `reserved_concurrent_executions` (Terraform) or `ReservedConcurrentExecutions` (CloudFormation/SAM) to that value.
3. Remember AWS always reserves a minimum unreserved pool (100 concurrent executions account-wide, subject to change) that cannot be fully allocated away — plan the sum of all functions' reserved concurrency accordingly, or the deployment will fail.
4. If a function should be prevented from running at all in some circumstance (e.g. an incident kill-switch), setting reserved concurrency to `0` throttles all invocations — a useful emergency control, but plan alerting so it isn't mistaken for an outage.
5. Monitor the `ConcurrentExecutions` and `Throttles` CloudWatch metrics after applying the limit to ensure it isn't set too low and causing unwanted throttling.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LambdaFunctionLevelConcurrentExecutionLimit.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/LambdaFunctionLevelConcurrentExecutionLimit.py
- AWS documentation: https://docs.aws.amazon.com/lambda/latest/dg/lambda-concurrency.html
