# CKV_AWS_224: Ensure ECS Cluster logging is enabled and client to container communication uses CMK
## Severity
**LOW** (score: 2.0/10)

ECS Exec sessions can carry sensitive command output and credentials; without CMK-encrypted logging of that channel, captured session data is protected only by default encryption, increasing exposure if log storage is compromised.

## Summary
This check ensures that when an ECS cluster (`aws_ecs_cluster`) enables ECS Exec logging, it also encrypts that logging (and the exec channel data) using a customer-managed KMS key, rather than logging in a way that isn't independently key-protected.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_ecs_cluster`

## Why it matters
This check builds on CKV_AWS_223 (which just verifies logging is not disabled) by additionally requiring that, when a `kms_key_id` is configured for the exec session channel, the resulting logs are also encrypted — either via CloudWatch Logs encryption (`cloud_watch_encryption_enabled`) or S3 encryption (`s3_bucket_encryption_enabled`). ECS Exec logs capture the commands and potentially the output of interactive sessions into production containers, which can include sensitive data displayed or manipulated during the session (environment variables, database query results, credentials typed into a shell, etc.). If these logs are stored without encryption enforced at the log-destination level, they become a secondary source of sensitive data exposure — an attacker who gains read access to the log group or S3 bucket (even without ECS Exec permissions themselves) could read historical session transcripts. Combining a CMK-protected exec channel with CMK-encrypted logs ensures both the live interactive channel and its audit trail are protected under keys your organization controls and can audit/revoke.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` (not a simple value check) with more intricate logic:
1. It reads `configuration[0].execute_command_configuration[0]`.
2. If `execute_command_configuration` is missing or logging is explicitly `["NONE"]`, the result is `UNKNOWN` (Checkov can't confirm a failure/pass without more context — note logging fully disabled here is not marked FAILED by this specific check, since that's CKV_AWS_223's job).
3. If logging is enabled (not `"NONE"`) **and** a `kms_key_id` is set on `execute_command_configuration`, the check then looks at the nested `log_configuration` block:
   - If `log_configuration.cloud_watch_encryption_enabled == [True]` **or** `log_configuration.s3_bucket_encryption_enabled == [True]`, the check **PASSES**.
   - Otherwise, the check **FAILS** (a KMS key is configured for the exec channel, but the resulting logs aren't confirmed to be encrypted).
4. If logging is enabled but no `kms_key_id` is set at all, the check falls through to **FAILED**.
5. If the `configuration` block structure doesn't match expectations, the result is `UNKNOWN`.

## Non-compliant example
```hcl
resource "aws_ecs_cluster" "example" {
  name = "example-cluster"

  configuration {
    execute_command_configuration {
      logging    = "OVERRIDE"
      kms_key_id = aws_kms_key.exec.arn

      log_configuration {
        cloud_watch_log_group_name = aws_cloudwatch_log_group.ecs_exec.name
      }
    }
  }
}
```

## Remediated example
```hcl
resource "aws_ecs_cluster" "example" {
  name = "example-cluster"

  configuration {
    execute_command_configuration {
      logging    = "OVERRIDE"
      kms_key_id = aws_kms_key.exec.arn

      log_configuration {
        cloud_watch_log_group_name       = aws_cloudwatch_log_group.ecs_exec.name
        cloud_watch_encryption_enabled   = true
      }
    }
  }
}
```

## Remediation steps
1. Ensure `execute_command_configuration.logging` is set to `"DEFAULT"` or `"OVERRIDE"` (not `"NONE"`) — see CKV_AWS_223.
2. Set `kms_key_id` on `execute_command_configuration` to a customer-managed KMS key, encrypting the exec data channel itself.
3. Inside `log_configuration`, set `cloud_watch_encryption_enabled = true` (if logging to CloudWatch) or `s3_bucket_encryption_enabled = true` (if logging to S3) so the resulting session logs are also encrypted.
4. Grant the ECS task role/execution role the necessary `kms:Decrypt`/`kms:GenerateDataKey` permissions on the CMK used for both the channel and the log destination (they may be the same or different keys).
5. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECSClusterLoggingEncryptedWithCMK.py)
- [AWS ECS Exec: Logging and auditing](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html)
