# CKV_AWS_298: Ensure DMS S3 uses Customer Managed Key (CMK)
## Severity
**HIGH** (score: 7.5/10)

This check verifies DMS S3 endpoints use a customer-managed KMS key; without it, replicated data in S3 still receives default encryption, so the risk is reduced control over key access rather than plaintext exposure.

## Summary
This check ensures that an `aws_dms_s3_endpoint` resource specifies a `kms_key_arn`, so data migrated/replicated to the S3 target endpoint is encrypted with a customer-managed KMS key rather than the AWS-managed default.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_dms_s3_endpoint`

## Why it matters
`aws_dms_s3_endpoint` is a dedicated DMS S3 target endpoint resource (distinct from the generic `aws_dms_endpoint`) used to land migrated database data in S3, often as part of a data lake or replication pipeline. This data typically includes full or partial copies of production database tables, which may contain PII, financial records, or other regulated data. Without a customer-managed key, encryption relies on the AWS-owned or S3-managed default key, meaning the organization cannot independently control who can decrypt the objects, cannot enforce a distinct rotation policy, and loses the ability to immediately cut off access by disabling a key in response to a suspected compromise. This directly affects data-at-rest protections required by frameworks like PCI DSS, HIPAA, and SOC 2.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (Python check) using `ANY_VALUE` as the expected value. It inspects the `kms_key_arn` attribute:
- **PASS** if `kms_key_arn` is set to any non-empty value.
- **FAIL** if `kms_key_arn` is missing or empty.

## Non-compliant example
```hcl
resource "aws_dms_s3_endpoint" "target" {
  endpoint_id   = "s3-target-endpoint"
  endpoint_type = "target"
  bucket_name   = "dms-data-lake-target"
  # kms_key_arn not set -> check FAILS
}
```

## Remediated example
```hcl
resource "aws_kms_key" "dms_s3" {
  description         = "CMK for DMS S3 target endpoint"
  enable_key_rotation = true
}

resource "aws_dms_s3_endpoint" "target" {
  endpoint_id   = "s3-target-endpoint"
  endpoint_type = "target"
  bucket_name   = "dms-data-lake-target"
  kms_key_arn   = aws_kms_key.dms_s3.arn   # customer-managed key
}
```

## Remediation steps
1. Create (or reuse) a dedicated CMK for DMS S3 target data, with `enable_key_rotation = true`.
2. Set `kms_key_arn` on the `aws_dms_s3_endpoint` resource to that key's ARN.
3. Grant the DMS service role and the target S3 bucket policy the required `kms:Decrypt`/`kms:GenerateDataKey*` permissions in the key policy — migration tasks will fail with access-denied errors otherwise.
4. Also verify the destination S3 bucket's default encryption configuration (`aws_s3_bucket_server_side_encryption_configuration`) references the same or a compatible CMK for defense in depth.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DMSS3UsesCMK.py)
