# CKV_AWS_268: Ensure that Comprehend Entity Recognizer's volume is encrypted by KMS using a customer managed Key (CMK)

## Severity
**HIGH** (score: 7.5/10)

The affected volume only holds transient training scratch data during Comprehend model training, so the exposure window and blast radius are narrower than for persisted data stores, even though the underlying training corpus can be sensitive.

## Summary
This check ensures that an Amazon Comprehend custom entity recognizer specifies a KMS key (`volume_kms_key_id`) to encrypt the storage volume attached to the ML compute resources used during training.

## Applicability
- **Terraform**: resource `aws_comprehend_entity_recognizer`

## Why it matters
During training, Comprehend provisions storage volumes that temporarily hold data derived from your training corpus (intermediate artifacts, cached data, processing scratch space). If this volume is not encrypted with a customer-managed key, that transient but potentially sensitive data is protected only by whatever default encryption applies, outside the organization's own key-management and audit controls. In multi-tenant or shared-infrastructure environments, and especially for compliance regimes that require encryption-key-level control over any storage touching sensitive training data (PII, healthcare, financial text), this gap in volume-level encryption is a real, if narrow, exposure — the compute volume is a distinct trust boundary from the training data source (S3) and from the resulting model artifact.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` on the `volume_kms_key_id` attribute:
- **PASS**: `volume_kms_key_id` is set to any non-empty value.
- **FAIL**: `volume_kms_key_id` is absent or empty.

## Non-compliant example
```hcl
resource "aws_comprehend_entity_recognizer" "custom_ner" {
  name                 = "custom-entities"
  data_access_role_arn = aws_iam_role.comprehend.arn
  language_code        = "en"

  input_data_config {
    entity_types {
      type = "PRODUCT"
    }
    documents {
      s3_uri = "s3://training-bucket/docs/"
    }
    annotations {
      s3_uri = "s3://training-bucket/annotations/"
    }
  }
  # no volume_kms_key_id set
}
```

## Remediated example
```hcl
resource "aws_comprehend_entity_recognizer" "custom_ner" {
  name                 = "custom-entities"
  data_access_role_arn = aws_iam_role.comprehend.arn
  language_code        = "en"
  volume_kms_key_id    = aws_kms_key.comprehend_volume.arn

  input_data_config {
    entity_types {
      type = "PRODUCT"
    }
    documents {
      s3_uri = "s3://training-bucket/docs/"
    }
    annotations {
      s3_uri = "s3://training-bucket/annotations/"
    }
  }
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key intended for Comprehend's training-volume encryption.
2. Set `volume_kms_key_id` on the `aws_comprehend_entity_recognizer` resource to that key's ARN or ID.
3. Grant the Comprehend service and `data_access_role_arn` the necessary `kms:Decrypt`/`kms:GenerateDataKey` permissions in the key policy.
4. Consider using the same or a paired key as `model_kms_key_id` (see CKV_AWS_267) for consistent key-based governance across the full training lifecycle.
5. As with the model key, this setting is fixed at training time — changing it requires creating a new recognizer version, not an in-place update.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ComprehendEntityRecognizerVolumeUsesCMK.py
- AWS documentation: https://docs.aws.amazon.com/comprehend/latest/dg/kms-in-comprehend.html
