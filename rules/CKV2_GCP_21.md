# CKV2_GCP_21: Ensure Vertex AI instance disks are encrypted with a Customer Managed Key (CMK)
## Severity
**MEDIUM** (score: 5.0/10)

Vertex AI notebook disks lacking a customer-managed key still receive Google-managed encryption at rest, so the gap is reduced key-control/rotation assurance for potentially sensitive ML data rather than unencrypted storage.

## Summary
This check ensures that Vertex AI (Notebooks) instance disks are encrypted using a customer-managed encryption key (CMEK) rather than relying solely on Google's default encryption.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_notebooks_instance`

## Why it matters
By default, GCP encrypts data at rest with Google-managed keys, which protects against physical media theft but gives the customer no control over key rotation, revocation, or access boundaries. Customer-Managed Encryption Keys (CMEK) via Cloud KMS let you control the key lifecycle, enforce separation of duties (the KMS key can be in a different project/IAM domain than the compute resource), and immediately revoke access to disk data by disabling or destroying the key — a critical control for regulated workloads (data residency, compliance frameworks like HIPAA/PCI, or contractual data-sovereignty requirements). Vertex AI notebook instances often hold sensitive training data, model artifacts, and credentials; without CMEK, an org loses this independent layer of cryptographic access control over that data.

## How Checkov evaluates this
This is a Terraform graph-based check requiring both of the following on `google_notebooks_instance`:
- The `kms_key` attribute exists (a KMS key is referenced), **and**
- `disk_encryption` is explicitly set to `"CMEK"`.
Both conditions must hold for a **PASS**; if either is missing (no `kms_key`, or `disk_encryption` left at the default `GMEK`/unset), the check **FAILS**.

## Non-compliant example
```hcl
resource "google_notebooks_instance" "notebook" {
  name     = "my-notebook"
  location = "us-central1-a"
  machine_type = "n1-standard-4"

  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }
  # disk_encryption defaults to GMEK, no kms_key set
}
```

## Remediated example
```hcl
resource "google_notebooks_instance" "notebook" {
  name          = "my-notebook"
  location      = "us-central1-a"
  machine_type  = "n1-standard-4"
  disk_encryption = "CMEK"
  kms_key         = google_kms_crypto_key.notebook_key.id

  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }
}

resource "google_kms_crypto_key" "notebook_key" {
  name     = "notebook-disk-key"
  key_ring = google_kms_key_ring.notebook_ring.id
}
```

## Remediation steps
1. Create (or identify) a Cloud KMS key ring and crypto key dedicated to Vertex AI notebook disk encryption.
2. Grant the Vertex AI/Compute Engine service agent the `roles/cloudkms.cryptoKeyEncrypterDecrypter` role on that key.
3. Set `disk_encryption = "CMEK"` and `kms_key = <key resource id>` on the `google_notebooks_instance` resource.
4. This setting is typically only configurable at instance creation time — changing it on an existing instance likely requires resource replacement (new instance, data migration).
5. Ensure the KMS key's location matches the notebook instance's region/zone requirements.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPVertexInstanceEncryptedWithCMK.json
- GCP docs: https://cloud.google.com/vertex-ai/docs/workbench/instances/encryption
