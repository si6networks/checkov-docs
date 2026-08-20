# CKV_AWS_301: Ensure that AWS Lambda function is not publicly accessible
## Severity
**LOW** (score: 2.0/10)

This check verifies a Lambda resource-based policy does not grant public invoke permission, and failing it means the function (and any data or downstream systems it can reach) is directly invocable by anyone on the internet.

## Summary
This check ensures that an `aws_lambda_permission` resource's `principal` is not set to the wildcard `"*"`, which would allow any AWS principal (or anyone, for certain invocation configurations) to invoke the Lambda function directly.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_lambda_permission`

## Why it matters
`aws_lambda_permission` defines the resource-based policy statement attached to a Lambda function, controlling who/what may invoke it. Setting `principal = "*"` grants invocation rights to any AWS account or, in unauthenticated invocation scenarios (e.g., paired with a Function URL configured for `AuthType = NONE`), effectively anyone on the internet. This exposes the function to unauthorized invocation, which can lead to: denial-of-wallet attacks (repeatedly invoking a function to run up billing costs), abuse of the function's IAM execution role privileges if the function performs privileged actions on invocation, exposure of any sensitive logic or data the function returns, and use of the function as a pivot point into other AWS resources it has access to (databases, internal APIs, secrets). This maps directly to PCI DSS network segmentation requirements and NIST 800-53 access control controls (AC-3, AC-4, AC-6, SC-7) — a Lambda function should generally only be invokable by specific, named services or principals (e.g., a specific API Gateway, S3 bucket, or EventBridge rule), never an unrestricted wildcard.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` (Python check) with `"*"` as the forbidden value. It inspects the `principal` attribute:
- **FAIL** if `principal = "*"`.
- **PASS** if `principal` is set to any specific value (e.g., a service principal like `apigateway.amazonaws.com`, a specific account ID, or ARN) other than the wildcard.

## Non-compliant example
```hcl
resource "aws_lambda_permission" "public_invoke" {
  statement_id  = "AllowPublicInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.example.function_name
  principal     = "*"   # allows anyone/anything to invoke -> check FAILS
}
```

## Remediated example
```hcl
resource "aws_lambda_permission" "apigw_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.example.function_name
  principal     = "apigateway.amazonaws.com"   # scoped to a specific service
  source_arn    = "${aws_api_gateway_rest_api.example.execution_arn}/*/*"
}
```

## Remediation steps
1. Replace `principal = "*"` with the specific AWS service principal (e.g., `apigateway.amazonaws.com`, `s3.amazonaws.com`, `events.amazonaws.com`) or specific AWS account ID that legitimately needs to invoke the function.
2. Always pair a service principal with a `source_arn` (and/or `source_account`) constraint to scope the permission down to a specific triggering resource, not just any resource of that service type across all AWS.
3. If the use case genuinely requires unauthenticated public invocation (e.g., a public webhook), use a Lambda Function URL with appropriate throttling/WAF protection instead of a wildcard resource policy, and add strong input validation and rate limiting inside the function.
4. Audit existing Lambda functions for wildcard resource policies using `aws lambda get-policy` and correct any found in production.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LambdaFunctionIsNotPublic.py)
