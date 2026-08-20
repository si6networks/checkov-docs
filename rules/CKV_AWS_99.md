# CKV_AWS_99: Ensure Glue Security Configuration Encryption is enabled

## Severity
**HIGH** (score: 7.5/10)

A Glue Security Configuration without encryption enabled leaves job data, logs, or bookmarks written without protection at rest, though exploitation still requires separate access to the underlying storage.

## Summary
This check fails unless an AWS Glue Security Configuration has encryption enabled across all three of its supported channels: CloudWatch Logs encryption, job bookmarks encryption, and S3 encryption.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_glue_security_configuration` resource — inspects `encryption_configuration[0].cloudwatch_encryption`, `.job_bookmarks_encryption`, and `.s3_encryption`.
- **CloudFormation**: `AWS::Glue::SecurityConfiguration` resource — inspects `Properties.EncryptionConfiguration.CloudWatchEncryption`, `.JobBookmarksEncryption`, and `.S3Encryptions`.

## Why it matters
A Glue Security Configuration is attached to Glue jobs/crawlers/dev endpoints to control encryption for everything they touch: CloudWatch Logs output (which can include job logs, error stack traces, and occasionally sample data used for debugging), job bookmarks (state used to track incremental ETL processing, stored in S3, which can reveal what data has and hasn't been processed), and the S3 output/target data itself. If any one of these channels is left unencrypted, that data is exposed to anyone with read access to the underlying storage — even if the rest of the pipeline is well protected — undermining the overall data protection posture for the ETL pipeline. Because these are the standard sinks for a Glue job's outputs and metadata, requiring encryption on all three closes an easy gap where sensitive data could otherwise land unencrypted despite the source/target databases themselves being encrypted.

## How Checkov evaluates this
Both implementations require all three flags to independently evaluate to `true`:
- **CloudWatch encryption**: `CloudWatchEncryptionMode`/`cloudwatch_encryption_mode` must not be `"DISABLED"` (Terraform additionally requires it to equal exactly `"SSE-KMS"` and requires `kms_key_arn` to be present).
- **Job bookmarks encryption**: `JobBookmarksEncryptionMode`/`job_bookmarks_encryption_mode` must not be `"DISABLED"` (Terraform requires it to equal `"CSE-KMS"` and requires `kms_key_arn`).
- **S3 encryption**: at least one `S3Encryptions`/`s3_encryption` entry must have `S3EncryptionMode`/`s3_encryption_mode` not equal to `"DISABLED"`.

Only if all three are satisfied does the check return PASSED; any single one being disabled or missing → FAILED. Note the Terraform implementation is stricter than the CloudFormation one in that it pins specific KMS modes (`SSE-KMS` for CloudWatch, `CSE-KMS` for job bookmarks) and additionally requires a `kms_key_arn` to be present, not just a non-`DISABLED` mode.

## Non-compliant example
```hcl
resource "aws_glue_security_configuration" "etl" {
  name = "etl-security-config"

  encryption_configuration {
    cloudwatch_encryption {
      cloudwatch_encryption_mode = "DISABLED"
    }
    job_bookmarks_encryption {
      job_bookmarks_encryption_mode = "DISABLED"
    }
    s3_encryption {
      s3_encryption_mode = "DISABLED"
    }
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "glue_logs" {
  description = "KMS key for Glue CloudWatch logs and bookmarks"
}

resource "aws_glue_security_configuration" "etl" {
  name = "etl-security-config"

  encryption_configuration {
    cloudwatch_encryption {
      cloudwatch_encryption_mode = "SSE-KMS"
      kms_key_arn                  = aws_kms_key.glue_logs.arn
    }
    job_bookmarks_encryption {
      job_bookmarks_encryption_mode = "CSE-KMS"
      kms_key_arn                      = aws_kms_key.glue_logs.arn
    }
    s3_encryption {
      s3_encryption_mode = "SSE-KMS"
      kms_key_arn           = aws_kms_key.glue_logs.arn
    }
  }
}
```

## Remediation steps
1. Create (or reuse) a KMS key for Glue's CloudWatch/bookmarks/S3 encryption needs.
2. Set `cloudwatch_encryption_mode = "SSE-KMS"` with `kms_key_arn`, `job_bookmarks_encryption_mode = "CSE-KMS"` with `kms_key_arn`, and `s3_encryption_mode = "SSE-KMS"` (or `SSE-S3`) with `kms_key_arn` if using KMS.
3. Grant the Glue service role `kms:Decrypt`/`kms:GenerateDataKey` permissions on the key.
4. Attach the resulting `aws_glue_security_configuration` to the relevant `aws_glue_job`, `aws_glue_crawler`, or `aws_glue_dev_endpoint` via their `security_configuration` argument — creating the security configuration alone does not enforce it on jobs that don't reference it.
5. Note that CloudWatch log encryption via a customer KMS key requires the CloudWatch Logs service principal to also have permission to use the key (grant `logs.<region>.amazonaws.com` access in the key policy).

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/GlueSecurityConfiguration.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/GlueSecurityConfiguration.py
- AWS docs: https://docs.aws.amazon.com/glue/latest/dg/encryption-security-configuration.html
