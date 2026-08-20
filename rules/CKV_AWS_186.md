# CKV_AWS_186: Ensure S3 bucket Object is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

This check enforces a customer-managed KMS key on S3 bucket objects rather than encryption presence, so the residual risk is reduced key-level access control and auditability, not unencrypted objects.

## Summary
This check requires that an `aws_s3_bucket_object` resource specify a customer-managed KMS key (`kms_key_id`) so the individual object is encrypted with a key your organization controls.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_s3_bucket_object` (the legacy/deprecated Terraform AWS provider resource, superseded by `aws_s3_object`)
- **Check type:** resource (attribute-value check)

## Why it matters
When objects are uploaded via Terraform (e.g., seeding configuration files, Lambda deployment packages, or static assets) without specifying a CMK, the object may be encrypted with SSE-S3 or the AWS-managed KMS key depending on the bucket's default encryption configuration — not necessarily the CMK your organization intends to enforce. This creates inconsistent encryption governance: some objects in the bucket may be protected by an auditable, revocable customer-managed key while others uploaded through Terraform bypass that control entirely. For objects containing credentials, deployment artifacts, or sensitive configuration, this gap means an attacker who gains read access to the bucket (or the AWS-managed key's broad default policy) could potentially read data that was assumed to be protected by stricter key governance.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `kms_key_id` attribute of `aws_s3_bucket_object`. It expects `ANY_VALUE` — any non-empty value passes; the check FAILS if `kms_key_id` is not set on the resource.

## Non-compliant example
```hcl
resource "aws_s3_bucket_object" "example" {
  bucket = aws_s3_bucket.example.id
  key    = "lambda/deploy.zip"
  source = "deploy.zip"
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

resource "aws_s3_bucket_object" "example" {
  bucket                 = aws_s3_bucket.example.id
  key                    = "lambda/deploy.zip"
  source                 = "deploy.zip"
  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.s3.arn
}
```

## Remediation steps
1. Create or select a customer-managed KMS key with a key policy limited to the principals that should read the object.
2. Set `server_side_encryption = "aws:kms"` and `kms_key_id` on the resource.
3. Prefer migrating to the newer `aws_s3_object` resource (the `aws_s3_bucket_object` resource is deprecated in the Terraform AWS provider) while adding the same `kms_key_id` argument.
4. Consider also setting bucket-level default encryption with the same CMK so any object uploaded outside of this specific resource inherits the correct key.
5. Ensure Terraform's execution role has `kms:GenerateDataKey` on the CMK to perform the upload.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3BucketObjectEncryptedWithCMK.py)
- [AWS S3 server-side encryption with KMS documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)
