# CKV_AWS_19: Ensure all data stored in the S3 bucket is securely encrypted at rest
## Severity
**LOW** (score: 2.0/10)

Unlike the CMK-specific checks, this one verifies that server-side encryption at rest is configured at all for S3 data (a frequent target for breaches), so a genuine failure here means sensitive object data could be stored unencrypted.

## Summary
This check requires that an S3 bucket has server-side encryption configured (either SSE-S3/`AES256` or SSE-KMS/`aws:kms`) for data stored at rest.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Resource/entity types:** `AWS::S3::Bucket` (CloudFormation); `aws_s3_bucket` and (via connection) `aws_s3_bucket_server_side_encryption_configuration` (Terraform, graph-based check)
- **Check type:** resource attribute check (CloudFormation), graph-based connection/attribute check (Terraform)

## Why it matters
S3 buckets are one of the most common sources of data breaches in cloud environments, and encryption at rest is a baseline control expected by essentially every compliance framework (PCI-DSS, HIPAA, SOC 2, ISO 27001, FedRAMP). While S3 does encrypt newly-uploaded objects with SSE-S3 by default account-wide since 2023, Terraform/CloudFormation configurations that were authored before this or that explicitly manage encryption can still leave gaps — particularly in older accounts, imported resources, or when a `aws_s3_bucket_server_side_encryption_configuration` resource exists but doesn't specify a valid algorithm. Explicit, codified encryption configuration ensures the setting is enforced by IaC rather than depending on implicit account defaults that could be silently changed, and using SSE-KMS in particular enables key-level access auditing and revocation on top of encryption. Failing to codify this leaves auditors and downstream engineers unable to verify from the Terraform/CloudFormation source alone that data is encrypted, and creates drift risk if someone manually disables encryption.

## How Checkov evaluates this
- **CloudFormation:** A `BaseResourceValueCheck` inspects `Properties/BucketEncryption/ServerSideEncryptionConfiguration/[0]/ServerSideEncryptionByDefault/SSEAlgorithm` on `AWS::S3::Bucket`. Notably, `missing_block_result` is set to `PASSED` — i.e., if the `BucketEncryption` block is entirely absent, the check passes by default (reflecting that S3 now defaults to SSE-S3 automatically). If the block *is* present, the algorithm value must be `AES256` or `aws:kms` to pass; any other/missing value fails.
- **Terraform:** Implemented as a graph-based JSON policy. It PASSES if any of these hold:
  1. `aws_s3_bucket.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm` is directly set to `aws:kms` or `AES256`, **or**
  2. No separate `aws_s3_bucket_server_side_encryption_configuration` resource is connected to the bucket AND no inline `server_side_encryption_configuration` attribute exists (i.e., nothing configured at all — implying reliance on the account default, similar to the CloudFormation "missing block passes" logic... note this branch actually requires attribute `not_exists` on both sides, functionally treating total absence as passing), **or**
  3. A connected `aws_s3_bucket_server_side_encryption_configuration` resource exists and its `rule.apply_server_side_encryption_by_default.sse_algorithm` is `aws:kms` or `AES256`.
  
  The failing case is when encryption configuration is explicitly present (inline or via the separate resource) but the algorithm is missing or not one of the two valid values.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "app-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    # apply_server_side_encryption_by_default block missing / no sse_algorithm set
  }
}
```

```yaml
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: "invalid-algo"
```

## Remediated example
```hcl
resource "aws_kms_key" "s3" {
  description             = "CMK for bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "example" {
  bucket = "app-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}
```

```yaml
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
              KMSMasterKeyID: !Ref S3KmsKey
```

## Remediation steps
1. Add a `BucketEncryption` (CloudFormation) or `aws_s3_bucket_server_side_encryption_configuration` (Terraform) block explicitly setting `SSEAlgorithm`/`sse_algorithm` to `aws:kms` or `AES256`.
2. Prefer `aws:kms` with a customer-managed key for auditability and revocability (see CKV_AWS_186 for per-object CMK enforcement); use `AES256` only when KMS overhead/cost is not justified.
3. If using KMS, ensure the bucket's IAM/key policies grant `kms:GenerateDataKey`/`kms:Decrypt` to the principals that need to read/write objects.
4. Do not rely solely on the account-wide default encryption (enabled automatically by AWS since January 2023) for compliance evidence — codify it explicitly in IaC so it's visible in code review and immune to account-level configuration drift.
5. Re-run Checkov after applying to confirm the algorithm value matches exactly `AES256` or `aws:kms` (case-sensitive).

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/S3Encryption.py)
- [Checkov check source (Terraform graph check)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/S3BucketEncryption.json)
- [AWS S3 default encryption documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html)
