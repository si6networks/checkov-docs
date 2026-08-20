# CKV_AWS_181: Ensure S3 Object Copy is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

The check enforces CMK usage on S3 object copy operations rather than the presence of encryption, so failure represents weaker key-level control/auditability, not unencrypted data at rest.

## Summary
This check requires that an `aws_s3_object_copy` resource specify a customer-managed KMS key (`kms_key_id`) so the copied object is encrypted at rest with a key your organization controls, rather than an AWS-managed key or SSE-S3.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_s3_object_copy`
- **Check type:** resource (attribute-value check)

## Why it matters
`aws_s3_object_copy` is used to copy an object from one S3 location to another as part of Terraform-managed infrastructure (e.g., seeding a bucket, replicating a template/config file). If the copy operation does not specify a CMK, the resulting object may end up with the default encryption of the destination bucket (which could be SSE-S3 or an AWS-managed KMS key) instead of a key your organization controls. Data that should be protected by an auditable, revocable customer-managed key can silently lose that protection during a copy, breaking the chain of custody for encryption control. This matters especially for compliance-sensitive data (PII, credentials, financial records) where the whole point of using CMKs is that access can be centrally audited and revoked — a copy operation that bypasses the CMK undermines that guarantee.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `kms_key_id` attribute on `aws_s3_object_copy`. It expects `ANY_VALUE` — any non-empty value passes; if the attribute is absent, the check FAILS.

## Non-compliant example
```hcl
resource "aws_s3_object_copy" "example" {
  bucket = "destination-bucket"
  key    = "config/app.json"
  source = "source-bucket/config/app.json"
  # kms_key_id not set
}
```

## Remediated example
```hcl
resource "aws_kms_key" "s3" {
  description             = "CMK for S3 object encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_s3_object_copy" "example" {
  bucket                 = "destination-bucket"
  key                    = "config/app.json"
  source                 = "source-bucket/config/app.json"
  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.s3.arn
}
```

## Remediation steps
1. Create or select a customer-managed KMS key with a key policy limiting decrypt access to authorized principals.
2. Set both `server_side_encryption = "aws:kms"` and `kms_key_id` on the `aws_s3_object_copy` resource.
3. Ensure the IAM principal executing the copy (Terraform's execution role) has `kms:GenerateDataKey` and `kms:Decrypt` permissions on the CMK, plus `kms:Decrypt` on the source object's key if it differs.
4. Where feasible, also enforce bucket-level default encryption with the same CMK so future uploads inherit it, rather than relying solely on per-object settings.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3ObjectCopyEncryptedWithCMK.py)
- [AWS S3 encryption documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)
