# CKV_AWS_296: Ensure DMS endpoint uses Customer Managed Key (CMK)
## Severity
**HIGH** (score: 7.5/10)

This check verifies DMS endpoints use a customer-managed KMS key for encryption; the underlying data is still encrypted by default AWS-managed keys, so missing a CMK reduces key governance/control rather than leaving replication data unencrypted.

## Summary
This check ensures that an `aws_dms_endpoint` resource encrypts its data with a customer-managed KMS key — either via `kms_key_arn` in general, or via `s3_settings.server_side_encryption_kms_key_id` specifically when the endpoint's `engine_name` is `"s3"`.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_dms_endpoint`

## Why it matters
AWS Database Migration Service (DMS) endpoints define source/target connections used to migrate or replicate potentially sensitive production data (customer records, financial data, credentials) between databases. If the endpoint relies on AWS-managed default encryption rather than a CMK, the organization loses direct control over the encryption key's access policy, rotation schedule, and the ability to revoke access to the encrypted data independently of AWS's own key management. For the S3-target case specifically, migrated data landing in S3 without a CMK-backed encryption key is protected only by the bucket's default (or AWS-managed) encryption, which is weaker from an access-control and auditability standpoint — anyone with S3 read permissions but no legitimate need for the underlying key could potentially access decrypted data if the default key's policy is overly permissive.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` (Python check) with branching logic:
- If `engine_name == "s3"`: it looks inside `s3_settings` for `server_side_encryption_kms_key_id`. **PASS** if that value is set; **FAIL** otherwise (including if `s3_settings` block is missing entirely).
- For all other engines: it looks at the top-level `kms_key_arn` attribute. **PASS** if set to a truthy value; **FAIL** if missing or empty.

## Non-compliant example
```hcl
resource "aws_dms_endpoint" "s3_target" {
  endpoint_id   = "s3-target"
  endpoint_type = "target"
  engine_name   = "s3"

  s3_settings {
    bucket_name = "dms-migration-target"
    # server_side_encryption_kms_key_id not set -> check FAILS
  }
}

resource "aws_dms_endpoint" "rds_target" {
  endpoint_id   = "rds-target"
  endpoint_type = "target"
  engine_name   = "postgres"
  server_name   = "target-db.example.com"
  port          = 5432
  username      = "dms_user"
  password      = var.db_password
  # kms_key_arn not set -> check FAILS
}
```

## Remediated example
```hcl
resource "aws_kms_key" "dms" {
  description         = "CMK for DMS endpoint encryption"
  enable_key_rotation = true
}

resource "aws_dms_endpoint" "s3_target" {
  endpoint_id   = "s3-target"
  endpoint_type = "target"
  engine_name   = "s3"

  s3_settings {
    bucket_name                       = "dms-migration-target"
    server_side_encryption_kms_key_id = aws_kms_key.dms.arn   # CMK for S3 target
  }
}

resource "aws_dms_endpoint" "rds_target" {
  endpoint_id   = "rds-target"
  endpoint_type = "target"
  engine_name   = "postgres"
  server_name   = "target-db.example.com"
  port          = 5432
  username      = "dms_user"
  password      = var.db_password
  kms_key_arn   = aws_kms_key.dms.arn   # CMK for the endpoint
}
```

## Remediation steps
1. Create a dedicated CMK for DMS (or reuse an approved one) with rotation enabled.
2. For non-S3 engines, set `kms_key_arn` on the `aws_dms_endpoint` resource.
3. For S3-engine endpoints, set `server_side_encryption_kms_key_id` inside the `s3_settings` block — setting only the top-level `kms_key_arn` will NOT satisfy this check when `engine_name = "s3"`.
4. Grant the DMS service role (and the S3 bucket, for S3 targets) the necessary `kms:Decrypt`/`kms:GenerateDataKey*` permissions in the CMK's key policy, or migration tasks will fail with access-denied errors.
5. Note this only covers the endpoint's own encryption setting; also verify the `aws_dms_replication_instance` and any target storage (RDS, S3 bucket) are separately configured for encryption at rest.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DMSEndpointUsesCMK.py)
