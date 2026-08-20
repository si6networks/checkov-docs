# CKV2_GCP_25: Ensure Vertex AI featurestore uses a Customer Managed Key (CMK)
## Severity
**MEDIUM** (score: 5.0/10)

Vertex AI featurestores without a CMK remain encrypted with Google-managed keys, so this narrows customer control over encryption keys protecting feature data rather than removing encryption entirely.

## Summary
This check ensures that a Vertex AI Featurestore resource defines an `encryption_spec` block, indicating use of a customer-managed encryption key (CMEK) rather than default Google-managed encryption.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_vertex_ai_featurestore`

## Why it matters
Vertex AI Featurestore centralizes and serves ML feature data — often derived directly from raw business or customer data used for model training and online prediction serving. This makes it a high-value, sensitive data repository at the heart of an ML pipeline. Relying only on Google-managed encryption means there's no independent cryptographic control boundary: the organization cannot rotate keys on its own schedule, cannot instantly revoke access to feature data by disabling a key, and cannot demonstrate the level of customer key control that many compliance frameworks (SOC 2, HIPAA, PCI-DSS) expect for sensitive data stores. Using CMEK closes this gap and integrates featurestore encryption into the organization's centralized Cloud KMS key management and audit trail.

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_vertex_ai_featurestore`:
- **PASS** if the `encryption_spec` attribute/block exists.
- **FAIL** if `encryption_spec` is absent.

## Non-compliant example
```hcl
resource "google_vertex_ai_featurestore" "featurestore" {
  name     = "my-featurestore"
  region   = "us-central1"
  # no encryption_spec -> Google-managed encryption only
}
```

## Remediated example
```hcl
resource "google_vertex_ai_featurestore" "featurestore" {
  name   = "my-featurestore"
  region = "us-central1"

  encryption_spec {
    kms_key_name = google_kms_crypto_key.featurestore_key.id
  }
}

resource "google_kms_crypto_key" "featurestore_key" {
  name     = "vertex-featurestore-key"
  key_ring = google_kms_key_ring.vertex_ring.id
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in the same region as the Featurestore.
2. Grant the Vertex AI service agent `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key.
3. Add an `encryption_spec { kms_key_name = <key id> }` block to the `google_vertex_ai_featurestore` resource.
4. CMEK is generally set at featurestore creation time and cannot be modified later — enabling this on an existing featurestore likely requires creating a new one and migrating feature data.
5. Verify all downstream feature-serving jobs and online-serving nodes have the required IAM permissions on the KMS key.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPVertexAIFeaturestoreEncryptedWithCMK.json
- GCP docs: https://cloud.google.com/vertex-ai/docs/general/cmek
