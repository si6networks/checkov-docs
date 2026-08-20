# CKV_AWS_267: Ensure that Comprehend Entity Recognizer's model is encrypted by KMS using a customer managed Key (CMK)

## Severity
**HIGH** (score: 7.5/10)

A Comprehend recognizer's trained model can indirectly encode signal from sensitive training data, but the check only enforces CMK-based key control on top of existing default encryption, limiting the exposure to audit and access-boundary gaps rather than plaintext leakage.

## Summary
This check ensures that an Amazon Comprehend custom entity recognizer specifies a KMS key (`model_kms_key_id`) to encrypt the trained model artifact.

## Applicability
- **Terraform**: resource `aws_comprehend_entity_recognizer`

## Why it matters
A Comprehend custom entity recognizer's trained model encodes patterns learned directly from the training data — which can include sensitive entity types, proprietary taxonomies, or information that indirectly reveals characteristics of the underlying (potentially confidential) training corpus. Leaving the model unencrypted by a customer-managed key means the organization cannot independently control, audit, or revoke access to the model artifact using its own key policy; it's left depending entirely on whatever default protections AWS provides, with no way to enforce least-privilege access to a specific model asset that might represent significant model-development investment or embed sensitive training signal.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` on the `model_kms_key_id` attribute:
- **PASS**: `model_kms_key_id` is set to any non-empty value.
- **FAIL**: `model_kms_key_id` is absent or empty.

## Non-compliant example
```hcl
resource "aws_comprehend_entity_recognizer" "custom_ner" {
  name     = "custom-entities"
  data_access_role_arn = aws_iam_role.comprehend.arn
  language_code = "en"

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
  # no model_kms_key_id set
}
```

## Remediated example
```hcl
resource "aws_comprehend_entity_recognizer" "custom_ner" {
  name                  = "custom-entities"
  data_access_role_arn  = aws_iam_role.comprehend.arn
  language_code         = "en"
  model_kms_key_id      = aws_kms_key.comprehend.arn

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
1. Create a dedicated CMK for Comprehend model artifacts, with rotation enabled.
2. Set `model_kms_key_id` on the `aws_comprehend_entity_recognizer` resource to that key's ARN or ID.
3. Update the key policy to allow the Comprehend service principal and the recognizer's `data_access_role_arn` (and any inference-time consumers) to use the key.
4. Note that `model_kms_key_id` is set at training/creation time; changing it requires retraining a new recognizer version (existing trained models cannot be re-encrypted in place), so plan for a retraining cycle.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ComprehendEntityRecognizerModelUsesCMK.py
- AWS documentation: https://docs.aws.amazon.com/comprehend/latest/dg/kms-in-comprehend.html
