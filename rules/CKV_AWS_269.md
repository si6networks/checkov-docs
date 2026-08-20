# CKV_AWS_269: Ensure Connect Instance Kinesis Video Stream Storage Config uses CMK

## Severity
**MEDIUM** (score: 5.0/10)

This storage config protects Amazon Connect call/media recordings, which routinely contain spoken PII and payment card data under PCI/HIPAA scope, so lacking a customer-managed key materially weakens access control and audit over highly sensitive recorded content.

## Summary
This check ensures that an Amazon Connect instance's Kinesis Video Stream storage configuration (used for call/chat/screen recordings) specifies a customer-managed KMS key for encryption.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: resource `aws_connect_instance_storage_config` (specifically the nested `kinesis_video_stream_config.encryption_config` block)

## Why it matters
Amazon Connect's Kinesis Video Stream storage is commonly used to capture and store contact-center media — call recordings, screen recordings — which routinely contain highly sensitive data: customer PII, payment card details spoken during calls, health information, or other regulated content depending on the industry. Encryption of this stream storage with a CMK is critical because it lets the organization enforce a strict key policy limiting exactly which roles can decrypt recorded media, apply independent rotation, and generate CloudTrail-auditable proof of who accessed recordings — often a hard compliance requirement (PCI DSS for card data spoken on calls, HIPAA for health information). Relying on default/AWS-owned encryption removes this customer-controlled access boundary over what is frequently an organization's most sensitive recorded data.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` looking at the deeply nested attribute path:
`storage_config/[0]/kinesis_video_stream_config/[0]/encryption_config/[0]/key_id`
- **PASS**: that `key_id` is set to any non-empty value.
- **FAIL**: the path is missing at any level, or `key_id` is empty.

## Non-compliant example
```hcl
resource "aws_connect_instance_storage_config" "kvs" {
  instance_id   = aws_connect_instance.main.id
  resource_type = "MEDIA_STREAMS"

  storage_config {
    kinesis_video_stream_config {
      prefix                 = "connect-media"
      retention_period_hours = 24
      # no encryption_config block
    }
  }
}
```

## Remediated example
```hcl
resource "aws_connect_instance_storage_config" "kvs" {
  instance_id   = aws_connect_instance.main.id
  resource_type = "MEDIA_STREAMS"

  storage_config {
    kinesis_video_stream_config {
      prefix                 = "connect-media"
      retention_period_hours = 24

      encryption_config {
        encryption_type = "KMS"
        key_id          = aws_kms_key.connect_media.arn
      }
    }
  }
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key intended for Connect media/recording storage, with `enable_key_rotation = true`.
2. Add an `encryption_config` block within `kinesis_video_stream_config`, setting `encryption_type = "KMS"` and `key_id` to that key's ARN.
3. Update the key policy to grant Amazon Connect's service principal and any downstream consumers (e.g., analytics pipelines, QA review tools) decrypt access.
4. Restrict key policy access tightly given the sensitivity of call recordings — treat this as equivalent to a PCI/PII data store.
5. Changing storage config encryption typically applies to newly recorded streams going forward; it does not retroactively re-encrypt already-stored recordings.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ConnectInstanceKinesisVideoStreamStorageConfigUsesCMK.py
- AWS documentation: https://docs.aws.amazon.com/connect/latest/adminguide/encrypt-recordings.html
