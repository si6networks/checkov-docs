# CKV_AWS_297: Ensure EventBridge Scheduler Schedule uses Customer Managed Key (CMK)
## Severity
**HIGH** (score: 7.5/10)

This check verifies EventBridge Scheduler schedules use a customer-managed KMS key; failing it weakens encryption-key ownership and rotation control over scheduled payloads rather than removing encryption entirely.

## Summary
This check ensures that an `aws_scheduler_schedule` resource specifies a `kms_key_arn`, so the schedule's target payload/configuration is encrypted with a customer-managed KMS key rather than the AWS-owned default key.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_scheduler_schedule`

## Why it matters
Amazon EventBridge Scheduler schedules can carry sensitive information in their target input payloads (e.g., parameters passed to a Lambda function, Step Functions execution input, or SQS message body), which may include business-sensitive data or references to credentials. Without a customer-managed key, this data at rest is protected only by AWS's default encryption, over which the organization has no policy control, no independent audit trail of decrypt operations, and no ability to revoke access or enforce separation of duties. Using a CMK lets security teams control exactly which principals/roles can decrypt schedule data, rotate the key on their own cadence, and correlate KMS CloudTrail events with schedule access for incident investigation.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (Python check) using `ANY_VALUE` as the expected value. It inspects the `kms_key_arn` attribute:
- **PASS** if `kms_key_arn` is set to any non-empty value.
- **FAIL** if `kms_key_arn` is missing or empty (default AWS-owned encryption is used).

## Non-compliant example
```hcl
resource "aws_scheduler_schedule" "nightly_job" {
  name       = "nightly-batch-job"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "cron(0 2 * * ? *)"

  target {
    arn      = aws_lambda_function.batch_job.arn
    role_arn = aws_iam_role.scheduler_role.arn
  }
  # kms_key_arn not set -> check FAILS
}
```

## Remediated example
```hcl
resource "aws_kms_key" "scheduler" {
  description         = "CMK for EventBridge Scheduler"
  enable_key_rotation = true
}

resource "aws_scheduler_schedule" "nightly_job" {
  name        = "nightly-batch-job"
  group_name  = "default"
  kms_key_arn = aws_kms_key.scheduler.arn   # customer-managed key

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "cron(0 2 * * ? *)"

  target {
    arn      = aws_lambda_function.batch_job.arn
    role_arn = aws_iam_role.scheduler_role.arn
  }
}
```

## Remediation steps
1. Create (or reuse) a CMK dedicated to EventBridge Scheduler, with automatic rotation enabled.
2. Set `kms_key_arn` on every `aws_scheduler_schedule` resource to that key's ARN.
3. Update the CMK's key policy to grant the EventBridge Scheduler service principal (`scheduler.amazonaws.com`) the necessary `kms:Decrypt` and `kms:GenerateDataKey` permissions, otherwise schedule creation or invocation may fail.
4. If schedules are created across multiple accounts/regions, ensure the KMS key policy and any cross-account grants are configured accordingly (KMS keys are regional).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SchedulerScheduleUsesCMK.py)
