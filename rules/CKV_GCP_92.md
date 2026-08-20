# CKV_GCP_92: Ensure Vertex AI datasets use a CMK (Customer Managed Key)
## Severity
**LOW** (score: 2.0/10)

Vertex AI datasets are encrypted by default, so lacking a CMK weakens customer control over the keys protecting potentially sensitive training data rather than exposing it unencrypted.

## Summary
This check requires `google_vertex_ai_dataset` resources to set `encryption_spec.kms_key_name`, so training/evaluation datasets managed in Vertex AI are encrypted at rest with a customer-managed Cloud KMS key.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_vertex_ai_dataset`
- **Check type:** resource (attribute-value check on the nested `encryption_spec` block)

## Why it matters
Vertex AI datasets store the labeled training/evaluation data feeding ML models — data that often includes sensitive inputs (customer records, images, telemetry, or other regulated data) and that, if exposed, can reveal both raw sensitive content and the characteristics of models trained on it. Without a customer-managed key, this data is protected only by Google-managed encryption, giving the organization no independent control over key rotation or a mechanism to revoke access decisively. CMEK lets you enforce the same key-custody and audit-trail requirements across your ML data pipeline as the rest of your regulated data estate, and provides a clean way to cryptographically destroy access to a dataset (e.g., for data-retention/right-to-erasure obligations) by disabling the key rather than relying solely on record-level deletion.

## How Checkov evaluates this
The check (`VertexAIDatasetEncryptedWithCMK`, a `BaseResourceValueCheck`) inspects the attribute path `encryption_spec/[0]/kms_key_name` on `google_vertex_ai_dataset`, checking against `ANY_VALUE`.
- **PASS**: `encryption_spec.kms_key_name` is set to a non-empty value.
- **FAIL**: `encryption_spec` or its `kms_key_name` is absent/empty.

## Non-compliant example
```hcl
resource "google_vertex_ai_dataset" "training_data" {
  display_name        = "training-dataset"
  metadata_schema_uri = "gs://google-cloud-aiplatform/schema/dataset/metadata/image_1.0.0.yaml"
  region               = "us-central1"
  # No encryption_spec -> Google-managed encryption only
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "vertex_ai" {
  name     = "vertex-ai-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "vertex_ai" {
  name     = "vertex-ai-dataset-key"
  key_ring = google_kms_key_ring.vertex_ai.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_vertex_ai_dataset" "training_data" {
  display_name        = "training-dataset"
  metadata_schema_uri = "gs://google-cloud-aiplatform/schema/dataset/metadata/image_1.0.0.yaml"
  region               = "us-central1"

  encryption_spec {
    kms_key_name = google_kms_crypto_key.vertex_ai.id
  }
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in the same region as the Vertex AI dataset.
2. Grant the Vertex AI service agent (`service-<PROJECT_NUMBER>@gcp-sa-aiplatform.iam.gserviceaccount.com`) `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key.
3. Add the `encryption_spec { kms_key_name = ... }` block to the dataset resource.
4. `encryption_spec` is set at creation time and cannot be changed on an existing dataset — you must create a new CMEK-enabled dataset and re-import/re-associate data and any dependent models/pipelines.
5. Confirm any downstream Vertex AI training jobs or pipelines that reference this dataset are updated to use the new dataset resource ID after migration.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/VertexAIDatasetEncryptedWithCMK.py
- GCP docs: https://cloud.google.com/vertex-ai/docs/general/cmek
