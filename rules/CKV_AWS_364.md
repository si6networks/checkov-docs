# CKV_AWS_364: Ensure that AWS Lambda function permissions delegated to AWS services are limited by SourceArn or SourceAccount

## Severity
**HIGH** (score: 7.5/10)

Granting an AWS service principal invoke access without scoping to SourceArn/SourceAccount is a textbook confused-deputy flaw letting any resource of that service type in any AWS account (e.g., an attacker's own S3 bucket or SNS topic) trigger the function with attacker-controlled input.

## Summary
This check ensures that when a Lambda resource-based policy (`aws_lambda_permission` / `AWS::Lambda::Permission`) grants invoke access to an AWS service principal (e.g. `s3.amazonaws.com`, `sns.amazonaws.com`), it also restricts *which* specific resource or account can invoke the function via `SourceArn` and/or `SourceAccount`.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::Lambda::Permission` (properties `Principal`, `SourceArn`, `SourceAccount`), `aws_lambda_permission` (attributes `principal`, `source_arn`, `source_account`)

## Why it matters
Granting a Lambda permission to a service principal like `s3.amazonaws.com` means *any* S3 bucket in *any* AWS account can potentially invoke your function, unless the permission is scoped down. This is a well-known "confused deputy" vulnerability pattern: an attacker who controls an S3 bucket (in their own account, or a compromised one) could configure event notifications pointing at your Lambda's ARN and invoke it with attacker-controlled input, provided they know or can guess the function ARN. Similar risk exists for SNS topics, CloudWatch Events/EventBridge rules, and other AWS services that invoke Lambda via resource-based policies — without `SourceArn` (scoping to a specific bucket/topic/rule ARN) or `SourceAccount` (scoping to your own AWS account), the trust boundary is effectively "the entire AWS service," not "my specific resource." AWS explicitly documents this confused-deputy risk and recommends both conditions together where possible.

## How Checkov evaluates this
Both implementations use custom `scan_resource_conf` logic:
1. Read the `Principal` (`principal` in Terraform) field.
2. Split it on `.` — if it matches the pattern `<service>.amazonaws.com` (i.e., segment 1 is `amazonaws` and segment 2 is `com`), it's confirmed to be an AWS service principal.
3. If it's a service principal:
   - If either `SourceArn`/`source_arn` **or** `SourceAccount`/`source_account` is present, the check **PASSES**.
   - If neither is present, the check **FAILS**.
4. If the principal doesn't parse as a service principal (e.g. it's a specific AWS account ID, an IAM ARN, or malformed), the result is **UNKNOWN** (not evaluated as pass/fail) since the check only targets service-principal delegation.

## Non-compliant example
```hcl
resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.processor.function_name
  principal     = "s3.amazonaws.com"
  # No source_arn or source_account -> any bucket in any account could invoke this function
}
```

## Remediated example
```hcl
resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.processor.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.uploads.arn
  source_account = data.aws_caller_identity.current.account_id
}
```

## Remediation steps
1. Add `source_arn` (Terraform) / `SourceArn` (CloudFormation) scoped to the exact resource ARN that should be allowed to invoke the function (e.g. the specific S3 bucket ARN, SNS topic ARN, or EventBridge rule ARN).
2. Where the service doesn't expose a granular resource ARN, or as defense-in-depth, also set `source_account` / `SourceAccount` to your own account ID to prevent cross-account invocation via a spoofed/similar resource name.
3. Prefer setting both conditions together when the service supports it (AWS explicitly recommends this for S3 notifications, per their confused-deputy guidance).
4. This is a mutable, low-risk change (no downtime) — apply, then verify the intended service integration (e.g. S3 event notification) still successfully invokes the function.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LambdaServicePermission.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/LambdaServicePermission.py
- AWS docs: https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html
- AWS confused deputy guidance: https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
