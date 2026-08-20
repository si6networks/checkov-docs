# CKV_AWS_158: Ensure that CloudWatch Log Group is encrypted by KMS
## Severity
**LOW** (score: 2.0/10)

CloudWatch Log Groups can capture application, access, and audit data that occasionally includes sensitive details (tokens, request bodies, identifiers), so encrypting them with a customer-managed key strengthens at-rest protection and key-level access control for that log data.

## Summary
This check verifies that a CloudWatch Logs log group has a KMS key configured for encrypting the log data at rest.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

Terraform (`aws_cloudwatch_log_group`) and CloudFormation (`AWS::Logs::LogGroup`).

## Why it matters
CloudWatch log groups frequently capture application logs, access logs, VPC flow logs, Lambda invocation logs, and API/audit logs, which can inadvertently include sensitive data — request bodies with PII, stack traces revealing internal architecture, tokens or session identifiers accidentally logged, database query parameters, or authentication attempts. By default, CloudWatch Logs encrypts data at rest with an AWS-owned key, which cannot be scoped by a custom key policy, so anyone with sufficiently broad IAM permission on `logs:GetLogEvents`/`logs:FilterLogEvents` can read the data — there's no independent gate at the encryption layer. Configuring a customer-managed KMS key lets you require an explicit `kms:Decrypt` grant on top of the CloudWatch Logs IAM permission, giving a genuine second layer of access control, full audit visibility via CloudTrail of every decrypt operation against the log group, and the ability to instantly revoke access account-wide by disabling the key.

## How Checkov evaluates this
`BaseResourceValueCheck` with `ANY_VALUE` as the expected value, inspecting `kms_key_id` (Terraform) / `Properties.KmsKeyId` (CloudFormation). Passes if the attribute is set to any non-empty value (any KMS key ARN); fails if absent, meaning the log group uses CloudWatch Logs' default AWS-owned encryption with no customer-managed key.

## Non-compliant example
```hcl
resource "aws_cloudwatch_log_group" "app" {
  name              = "/aws/lambda/app-handler"
  retention_in_days = 90
  # no kms_key_id -> encrypted with AWS-owned key only
}
```

## Remediated example
```hcl
resource "aws_kms_key" "logs" {
  description             = "CMK for CloudWatch Logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/aws/lambda/app-handler"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.logs.arn # <-- added
}
```

## Remediation steps
1. Create a customer-managed KMS key (or reuse an org-standard logging CMK) with a key policy that allows the CloudWatch Logs service principal (`logs.<region>.amazonaws.com`) to encrypt/decrypt on behalf of the log group.
2. Set `kms_key_id` (Terraform) or `KmsKeyId` (CloudFormation) on every `aws_cloudwatch_log_group`/`AWS::Logs::LogGroup` resource.
3. Grant `kms:Decrypt` in the key policy to whichever IAM principals should be able to read log content, and deliberately exclude broad roles.
4. Note: assigning a KMS key to an existing log group only affects data written after the change — historical log events remain under the previous encryption state.
5. Ensure the key's region matches the log group's region; cross-region KMS keys cannot be used for CloudWatch Logs encryption.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudWatchLogGroupKMSKey.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/CloudWatchLogGroupKMSKey.py
- AWS docs: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html
