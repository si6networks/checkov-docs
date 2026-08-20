# CKV2_GCP_24: Ensure Vertex AI endpoint uses a Customer Managed Key (CMK)
## Severity
**MEDIUM** (score: 5.0/10)

Vertex AI endpoints without a CMK still benefit from default encryption at rest, so the missing control is over key ownership/rotation for served model artifacts rather than a direct data exposure.

## Summary
This check ensures that a Vertex AI Endpoint resource defines an `encryption_spec` block, indicating use of a customer-managed encryption key (CMEK) rather than default Google-managed encryption.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_vertex_ai_endpoint`

## Why it matters
A Vertex AI Endpoint hosts deployed ML models that serve predictions, and its metadata/associated artifacts can include proprietary model data, deployment configuration, and derived outputs of potentially sensitive training data. Without a customer-managed key, the organization forfeits independent control over encryption key lifecycle for this resource — it cannot enforce its own rotation cadence, cannot centrally audit key usage across projects via Cloud KMS, and cannot revoke cryptographic access without deleting the resource. For organizations running proprietary or regulated ML models (e.g., healthcare diagnostics, financial risk scoring), CMEK is often a baseline compliance requirement to demonstrate control over encryption for model artifacts and any cached prediction data.

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_vertex_ai_endpoint`:
- **PASS** if the `encryption_spec` attribute/block exists.
- **FAIL** if `encryption_spec` is absent.
Note: the check only verifies that an `encryption_spec` block is present; it does not further validate the specific KMS key referenced inside it.

## Non-compliant example
```hcl
resource "google_vertex_ai_endpoint" "endpoint" {
  name         = "my-endpoint"
  display_name = "prod-model-endpoint"
  location     = "us-central1"
  # no encryption_spec -> Google-managed encryption only
}
```

## Remediated example
```hcl
resource "google_vertex_ai_endpoint" "endpoint" {
  name         = "my-endpoint"
  display_name = "prod-model-endpoint"
  location     = "us-central1"

  encryption_spec {
    kms_key_name = google_kms_crypto_key.endpoint_key.id
  }
}

resource "google_kms_crypto_key" "endpoint_key" {
  name     = "vertex-endpoint-key"
  key_ring = google_kms_key_ring.vertex_ring.id
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in the same region as the Vertex AI Endpoint.
2. Grant the Vertex AI service agent the `roles/cloudkms.cryptoKeyEncrypterDecrypter` role on the key.
3. Add an `encryption_spec { kms_key_name = <key id> }` block to the `google_vertex_ai_endpoint` resource.
4. CMEK is normally set at endpoint creation and cannot be changed afterward — updating this on an existing endpoint will likely require recreating the endpoint (and redeploying models to it), so plan for a cutover window.
5. Confirm all deployed models on the endpoint are compatible with CMEK-encrypted endpoints in your target region.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPVertexAIEndpointEncryptedWithCMK.json
- GCP docs: https://cloud.google.com/vertex-ai/docs/general/cmek
