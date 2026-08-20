# CKV_AWS_270: Ensure Connect Instance S3 Storage Config uses CMK

## Severity
**HIGH** (score: 7.5/10)

This S3 storage config holds contact-center call recordings and transcripts that commonly include regulated PII and payment data, so the absence of a customer-managed key removes a compliance-critical layer of key-level access control and audit over that sensitive content.

## Summary
This check ensures that an Amazon Connect instance's S3 storage configuration (used for call recordings, chat transcripts, exported reports, etc.) specifies a customer-managed KMS key for encryption.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: resource `aws_connect_instance_storage_config` (specifically the nested `s3_config.encryption_config` block)

## Why it matters
Amazon Connect writes numerous artifacts to S3 as part of contact-center operations: call recordings, chat transcripts, scheduled reports, and exported analytics — all of which can contain customer PII, payment information referenced during calls, or other regulated data. If this S3 storage configuration doesn't specify a customer-managed key, encryption falls back to defaults outside the organization's direct control, meaning the organization cannot enforce a dedicated key policy scoping exactly which principals may decrypt these artifacts, cannot apply independent rotation, and loses a CloudTrail-auditable record of every decrypt event tied specifically to this sensitive data store. This is frequently a hard requirement under PCI DSS (given the likelihood of card data mentioned on recorded calls) and other data-protection regimes governing contact-center data.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` looking at the nested attribute path:
`storage_config/[0]/s3_config/[0]/encryption_config/[0]/key_id`
- **PASS**: that `key_id` is set to any non-empty value.
- **FAIL**: the path is missing at any level, or `key_id` is empty.

## Non-compliant example
```hcl
resource "aws_connect_instance_storage_config" "call_recordings" {
  instance_id   = aws_connect_instance.main.id
  resource_type = "CALL_RECORDINGS"

  storage_config {
    s3_config {
      bucket_name = aws_s3_bucket.recordings.bucket
      bucket_prefix = "call-recordings"
      # no encryption_config block
    }
  }
}
```

## Remediated example
```hcl
resource "aws_connect_instance_storage_config" "call_recordings" {
  instance_id   = aws_connect_instance.main.id
  resource_type = "CALL_RECORDINGS"

  storage_config {
    s3_config {
      bucket_name   = aws_s3_bucket.recordings.bucket
      bucket_prefix = "call-recordings"

      encryption_config {
        encryption_type = "KMS"
        key_id          = aws_kms_key.connect_s3.arn
      }
    }
  }
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key dedicated to Connect's S3-stored artifacts, with rotation enabled.
2. Add an `encryption_config` block within `s3_config`, setting `encryption_type = "KMS"` and `key_id` to that key's ARN.
3. Grant Amazon Connect's service principal and any downstream analytics/QA consumers `kms:Decrypt`/`kms:GenerateDataKey` permissions on the key.
4. Also confirm the destination S3 bucket's own default encryption/bucket policy is consistent with (and doesn't override or conflict with) this KMS configuration.
5. This setting applies going forward to newly written objects; existing objects already stored under a different key are not retroactively re-encrypted.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ConnectInstanceS3StorageConfigUsesCMK.py
- AWS documentation: https://docs.aws.amazon.com/connect/latest/adminguide/encrypt-recordings.html
