# CKV_GCP_96: Ensure Vertex AI Metadata Store uses a CMK (Customer Managed Key)
## Severity
**LOW** (score: 2.0/10)

Vertex AI Metadata Store content is encrypted by default, so lacking a CMK is a key-management control gap over ML metadata rather than a lack of encryption.

## Summary
This check requires `google_vertex_ai_metadata_store` resources to set `encryption_spec.kms_key_name`, so ML pipeline/experiment metadata is encrypted at rest with a customer-managed Cloud KMS key.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_vertex_ai_metadata_store`
- **Check type:** resource (attribute-value check on the nested `encryption_spec` block)

## Why it matters
Vertex AI Metadata Store records lineage and metadata for ML artifacts, executions, and pipeline runs — including references to datasets, model parameters, evaluation metrics, and artifact URIs. This metadata can indirectly expose sensitive details about training data provenance, business logic embedded in feature engineering, or model performance characteristics that are themselves considered proprietary/sensitive. Relying only on Google-managed encryption denies the organization independent control over key rotation and revocation for this metadata store, which is inconsistent with an organization-wide CMEK policy applied to the rest of the Vertex AI/ML data estate (datasets, models, etc.). CMEK closes this gap and ensures a uniform key-custody boundary across the full ML pipeline's data and metadata.

## How Checkov evaluates this
The check (`VertexAIMetadataStoreEncryptedWithCMK`, a `BaseResourceValueCheck`) inspects the attribute path `encryption_spec/[0]/kms_key_name` on `google_vertex_ai_metadata_store`, checking against `ANY_VALUE`.
- **PASS**: `encryption_spec.kms_key_name` is set to a non-empty value.
- **FAIL**: `encryption_spec` or its `kms_key_name` is absent/empty.

## Non-compliant example
```hcl
resource "google_vertex_ai_metadata_store" "store" {
  name   = "default"
  region = "us-central1"
  # No encryption_spec -> Google-managed encryption only
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "vertex_ai" {
  name     = "vertex-ai-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "vertex_ai_metadata" {
  name     = "vertex-ai-metadata-key"
  key_ring = google_kms_key_ring.vertex_ai.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_vertex_ai_metadata_store" "store" {
  name   = "default"
  region = "us-central1"

  encryption_spec {
    kms_key_name = google_kms_crypto_key.vertex_ai_metadata.id
  }
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in the same region as the metadata store.
2. Grant the Vertex AI service agent (`service-<PROJECT_NUMBER>@gcp-sa-aiplatform.iam.gserviceaccount.com`) `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key.
3. Add the `encryption_spec { kms_key_name = ... }` block to the resource.
4. Note that a project typically has a single default metadata store per region; `encryption_spec` is set at creation and cannot be changed afterward, so if a store already exists without CMEK it must be deleted and recreated (which discards existing lineage/metadata) — plan this migration carefully and coordinate with any teams depending on existing pipeline lineage records.
5. Keep the crypto key protected with `prevent_destroy` (see CKV_GCP_82) to avoid orphaning the metadata store.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/VertexAIMetadataStoreEncryptedWithCMK.py
- GCP docs: https://cloud.google.com/vertex-ai/docs/general/cmek
