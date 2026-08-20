# CKV_AWS_145: Ensure that S3 buckets are encrypted with KMS by default
## Severity
**LOW** (score: 2.0/10)

S3 buckets frequently hold sensitive data, and this check ensures encryption at rest uses a customer-managed KMS key by default, so missing it means new objects can land unencrypted or under a less-controlled key, weakening data-at-rest protection and key-access auditability for the bucket.

## Summary
This check verifies that an S3 bucket's default server-side encryption uses `aws:kms` (a KMS key) rather than plain `AES256` (Amazon-managed SSE-S3 encryption) or no default encryption at all.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to `aws_s3_bucket` (legacy inline `server_side_encryption_configuration` block) and the standalone `aws_s3_bucket_server_side_encryption_configuration` resource.

## Why it matters
SSE-S3 (`AES256`) encrypts data at rest, but AWS fully controls the key — there is no way to restrict, audit, or revoke access to that key independently of S3 permissions, and no customer-controlled key rotation or usage logging. SSE-KMS lets you use a customer-managed key (CMK) with its own IAM/key policy, giving you: fine-grained control over who can decrypt objects (separate from who can read from the bucket), a full audit trail in CloudTrail of every `Decrypt`/`GenerateDataKey` call, the ability to disable or destroy the key to instantly cut off data access, and support for cross-account access patterns that require explicit key-policy grants. Relying on SSE-S3 makes it harder to prove strong access controls for regulated data and removes a key layer of defense-in-depth if bucket policies are misconfigured.

## How Checkov evaluates this
Graph-based check. Passes if either:
1. The `aws_s3_bucket` resource has inline `server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm` equal to `"aws:kms"`, OR
2. The `aws_s3_bucket` is connected to an `aws_s3_bucket_server_side_encryption_configuration` resource whose `rule.apply_server_side_encryption_by_default.sse_algorithm` equals `"aws:kms"`.

Any bucket with no default encryption configuration, or with `sse_algorithm = "AES256"`, fails.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "logs" {
  bucket = "app-logs-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "s3" {
  description             = "CMK for S3 default encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "logs" {
  bucket = "app-logs-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms" # <-- changed from AES256
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}
```

## Remediation steps
1. Create (or identify) a customer-managed KMS key dedicated to this bucket's data, with `enable_key_rotation = true`.
2. Set `sse_algorithm = "aws:kms"` and provide `kms_master_key_id` pointing at that CMK.
3. Grant the CMK's key policy access to the specific IAM roles/services that need to read/write objects (S3 alone being in the bucket policy is not enough — KMS decrypt permission is also required).
4. Be aware SSE-KMS incurs per-request KMS API charges and may need increased KMS request quotas for high-throughput workloads.
5. If migrating an existing bucket from SSE-S3 to SSE-KMS, existing objects are not re-encrypted automatically — only new writes use the new default; re-upload or use S3 Batch Operations to re-encrypt existing objects if required.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/S3KMSEncryptedByDefault.json
- AWS docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html
