# CKV2_GCP_35: Ensure Vertex AI runtime is encrypted with a Customer Managed Key (CMK)

## Severity
**MEDIUM** (score: 5.0/10)

Missing CMK encryption on Vertex AI notebook runtime storage weakens defense-in-depth for data-at-rest but does not by itself expose data or grant access, so it lands as a medium encryption-hygiene gap rather than a direct exploitation path.

## Summary
This check ensures that a Google Cloud Vertex AI (Notebooks) runtime's underlying virtual machine is encrypted using a customer-managed encryption key (CMEK) rather than relying solely on Google's default encryption.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_notebooks_runtime`

This is a graph-based check (Checkov "graph check", defined as JSON) rather than a Python check.

## Why it matters
Vertex AI Workbench / Notebooks runtimes can contain sensitive training data, credentials, notebooks with embedded secrets, and intermediate model artifacts on their attached VM disks. By default, Google encrypts data at rest with Google-managed keys, but that gives the account owner no control over key rotation, revocation, or access auditing. If an attacker (or a malicious insider) compromises the underlying storage layer, or if the organization needs to demonstrate compliance with regulations that require customer control over encryption keys (e.g., HIPAA, PCI-DSS, or internal data-residency policies), the lack of a CMK means the organization cannot immediately revoke access to encrypted data by disabling the key. Using a CMK also enables centralized key management, key rotation schedules, and separation of duties between the team that manages the compute and the team that manages the encryption keys.

## How Checkov evaluates this
The check inspects the Terraform resource `google_notebooks_runtime` for the attribute path `virtual_machine.virtual_machine_config.encryption_config.kms_key`. The graph check uses the `jsonpath_exists` operator: if this attribute exists anywhere in the resource configuration, the check **passes**; if the field is absent entirely, the check **fails**. There is no value validation beyond existence — any non-null KMS key reference satisfies the check.

## Non-compliant example
```hcl
resource "google_notebooks_runtime" "insecure" {
  name     = "my-notebook-runtime"
  location = "us-central1"

  virtual_machine {
    virtual_machine_config {
      machine_type = "n1-standard-4"

      # No encryption_config block -> no CMK, uses Google-managed key
    }
  }
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "notebooks" {
  name     = "notebooks-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "notebooks" {
  name     = "notebooks-cmk"
  key_ring = google_kms_key_ring.notebooks.id
}

resource "google_notebooks_runtime" "secure" {
  name     = "my-notebook-runtime"
  location = "us-central1"

  virtual_machine {
    virtual_machine_config {
      machine_type = "n1-standard-4"

      encryption_config {
        kms_key = google_kms_crypto_key.notebooks.id
      }
    }
  }
}
```

## Remediation steps
1. Create (or identify) a Cloud KMS key ring and crypto key dedicated to Vertex AI runtime encryption.
2. Grant the Vertex AI / Notebooks service account the `roles/cloudkms.cryptoKeyEncrypterDecrypter` role on that key.
3. Add an `encryption_config { kms_key = ... }` block inside `virtual_machine_config` of the `google_notebooks_runtime` resource, referencing the crypto key's resource ID.
4. Note: enabling CMEK on an existing runtime typically requires recreating the runtime (Terraform will show a replacement), since encryption configuration is generally immutable post-creation — plan for a maintenance window.
5. Establish a key rotation policy on the KMS key and monitor key usage via Cloud Audit Logs.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPVertexRuntimeEncryptedWithCMK.json
- Google Cloud docs: https://cloud.google.com/kms/docs/cmek
