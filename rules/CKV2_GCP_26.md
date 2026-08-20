# CKV2_GCP_26: Ensure Vertex AI tensorboard uses a Customer Managed Key (CMK)
## Severity
**MEDIUM** (score: 5.0/10)

Vertex AI tensorboards without a CMK still use default encryption at rest, making this a key-management control gap over experiment/metric data rather than an unencrypted-storage issue.

## Summary
This check ensures that a Vertex AI Tensorboard resource defines an `encryption_spec` block, indicating use of a customer-managed encryption key (CMEK) rather than default Google-managed encryption.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_vertex_ai_tensorboard`

## Why it matters
Vertex AI Tensorboard stores ML experiment tracking data: training metrics, hyperparameters, model graphs, and sometimes embedded sample data used to visualize model behavior. This can reveal proprietary model architecture details or leak information about the training dataset. Without a customer-managed key, the organization has no independent means to revoke cryptographic access to this experiment data or align its rotation schedule with internal key-management policy. CMEK support lets security teams centralize control of encryption for this experiment-tracking data alongside the rest of the ML pipeline, satisfying data-governance and compliance requirements around control of encryption keys for sensitive workloads.

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_vertex_ai_tensorboard`:
- **PASS** if the `encryption_spec` attribute/block exists.
- **FAIL** if `encryption_spec` is absent.

## Non-compliant example
```hcl
resource "google_vertex_ai_tensorboard" "tensorboard" {
  display_name = "experiment-tracking"
  region       = "us-central1"
  # no encryption_spec -> Google-managed encryption only
}
```

## Remediated example
```hcl
resource "google_vertex_ai_tensorboard" "tensorboard" {
  display_name = "experiment-tracking"
  region       = "us-central1"

  encryption_spec {
    kms_key_name = google_kms_crypto_key.tensorboard_key.id
  }
}

resource "google_kms_crypto_key" "tensorboard_key" {
  name     = "vertex-tensorboard-key"
  key_ring = google_kms_key_ring.vertex_ring.id
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in the same region as the Tensorboard resource.
2. Grant the Vertex AI service agent `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key.
3. Add an `encryption_spec { kms_key_name = <key id> }` block to the `google_vertex_ai_tensorboard` resource.
4. CMEK is set at creation time; enabling it on an existing Tensorboard instance will likely require creating a new resource and migrating logged experiment data.
5. Confirm training jobs writing to the Tensorboard have the required KMS IAM permissions after the change.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPVertexAITensorboardEncryptedWithCMK.json
- GCP docs: https://cloud.google.com/vertex-ai/docs/general/cmek
