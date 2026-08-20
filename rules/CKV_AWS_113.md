# CKV_AWS_113: Ensure Session Manager logs are enabled and encrypted

## Severity
**MEDIUM** (score: 5.0/10)

Disabled or unencrypted logging of privileged interactive Session Manager activity removes the audit trail needed to detect and investigate misuse of shell access to production systems.

## Summary
Fails when an AWS Systems Manager (SSM) `Session` document does not configure logging to either an encrypted S3 bucket or an encrypted CloudWatch Logs group.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_ssm_document` resource, specifically ones where `document_type = "Session"`.

## Why it matters
Session Manager sessions grant interactive shell access to managed instances. Without session logging, there is no durable audit trail of what commands were run, what files were viewed, or what data was accessed during a session — a significant gap for incident response, forensics, and compliance (e.g. PCI-DSS, SOC 2, HIPAA all require privileged-access logging). Even when logging is enabled, if the log destination itself isn't encrypted, the logs — which can contain sensitive command output, credentials, or data snippets typed/displayed during the session — become a secondary exposure point: anyone with read access to the unencrypted S3 bucket or CloudWatch Logs group can read session transcripts without needing the KMS key that would otherwise gate access.

## How Checkov evaluates this
Same parsing logic as CKV_AWS_112 (only evaluates `document_type == ["Session"]` resources with a `content` block, parses JSON/YAML/dict `content` to extract `inputs`), then:
- **PASS** if `inputs.s3BucketName` AND `inputs.s3EncryptionEnabled` are both truthy, OR if `inputs.cloudWatchLogGroupName` AND `inputs.cloudWatchEncryptionEnabled` are both truthy.
- **FAIL** if `inputs` exists but neither of the above pairs is satisfied (e.g. logging destination configured but its encryption flag is false/missing, or no destination configured at all).
- **UNKNOWN** if `inputs` couldn't be determined (e.g. document type isn't `Session`, or content couldn't be parsed).

## Non-compliant example
```hcl
resource "aws_ssm_document" "session" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    sessionType   = "Standard_Stream"
    inputs = {
      s3BucketName        = "session-logs-bucket"
      s3EncryptionEnabled = false
      kmsKeyId            = ""
    }
  })
}
```

## Remediated example
```hcl
resource "aws_ssm_document" "session" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    sessionType   = "Standard_Stream"
    inputs = {
      s3BucketName        = aws_s3_bucket.session_logs.id
      s3EncryptionEnabled = true
      kmsKeyId            = aws_kms_key.session_manager.key_id
    }
  })
}

resource "aws_s3_bucket" "session_logs" {
  bucket = "session-logs-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "session_logs" {
  bucket = aws_s3_bucket.session_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.session_manager.arn
    }
  }
}

resource "aws_kms_key" "session_manager" {
  description         = "CMK for Session Manager logging and encryption"
  enable_key_rotation = true
}
```

## Remediation steps
1. Choose a logging destination: an S3 bucket, a CloudWatch Logs group, or both.
2. If using S3: set `s3BucketName` to a real bucket and set `s3EncryptionEnabled = true`, and separately ensure the bucket itself has default SSE (ideally SSE-KMS) enabled via `aws_s3_bucket_server_side_encryption_configuration`.
3. If using CloudWatch Logs: set `cloudWatchLogGroupName` and `cloudWatchEncryptionEnabled = true`, and ensure the target `aws_cloudwatch_log_group` has a `kms_key_id` set for encryption at rest.
4. Verify IAM roles used by target instances have permission to write to the chosen log destination (`s3:PutObject` / `logs:PutLogEvents` as applicable) and, if KMS-encrypted, `kms:GenerateDataKey`.
5. Consider also enabling this at the account-level Session Manager preferences (console: Systems Manager > Session Manager > Preferences) for consistency, since this Terraform check only covers custom `aws_ssm_document` resources.
6. No downtime/replacement required; this is a configuration-only change picked up by new sessions.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SSMSessionManagerDocumentLogging.py
- AWS documentation: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-logging.html
