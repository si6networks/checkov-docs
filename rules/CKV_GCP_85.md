# CKV_GCP_85: Ensure Big Table Instances are encrypted with Customer Supplied Encryption Keys (CSEK)
## Severity
**LOW** (score: 2.0/10)

Bigtable data is encrypted by default with Google-managed keys, so missing CMK configuration weakens key-management control over potentially sensitive stored data rather than eliminating encryption entirely.

## Summary
This check requires each cluster in a `google_bigtable_instance` Terraform resource to set `kms_key_name`, so Bigtable data at rest is protected by a customer-managed Cloud KMS key rather than Google's default encryption.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_bigtable_instance`
- **Check type:** resource (attribute-value check on the nested `cluster` block)

## Why it matters
Cloud Bigtable is frequently used for large-scale, low-latency operational data (time-series, telemetry, user activity, ML feature stores) that can contain sensitive or regulated data. Without CMEK, the encryption key lifecycle is entirely controlled by Google, meaning the customer cannot independently rotate, restrict, or revoke the key that protects the data, and cannot demonstrate the level of key custody many compliance frameworks (PCI-DSS, HIPAA, FedRAMP) require. CMEK also gives you a "kill switch": disabling the KMS key immediately makes the Bigtable data inaccessible, which is valuable for incident containment (e.g., a compromised service account cannot exfiltrate readable data even if it retains Bigtable read access, once the key is revoked) and for guaranteed data destruction at end-of-life.

## How Checkov evaluates this
The check (`BigTableInstanceEncryptedWithCMK`, a `BaseResourceValueCheck`) inspects the attribute path `cluster/[0]/kms_key_name` on `google_bigtable_instance`, checking against `ANY_VALUE`.
- **PASS**: the first `cluster` block sets `kms_key_name` to a non-empty value.
- **FAIL**: `kms_key_name` is absent or empty in the first cluster block.

Note: because the checked path is `cluster/[0]/...`, only the *first* declared `cluster` block is inspected; if an instance has multiple clusters, ensure all of them set `kms_key_name` even though Checkov's attribute-value check primarily verifies the first one.

## Non-compliant example
```hcl
resource "google_bigtable_instance" "telemetry" {
  name = "telemetry-instance"

  cluster {
    cluster_id   = "telemetry-cluster"
    zone         = "us-central1-b"
    num_nodes    = 3
    storage_type = "SSD"
    # No kms_key_name -> Google-managed encryption only
  }
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "bigtable" {
  name     = "bigtable-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "bigtable" {
  name     = "bigtable-key"
  key_ring = google_kms_key_ring.bigtable.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_bigtable_instance" "telemetry" {
  name = "telemetry-instance"

  cluster {
    cluster_id   = "telemetry-cluster"
    zone         = "us-central1-b"
    num_nodes    = 3
    storage_type = "SSD"
    kms_key_name = google_kms_crypto_key.bigtable.id
  }
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in a location matching the Bigtable cluster's region.
2. Grant the Bigtable service agent (`service-<PROJECT_NUMBER>@gcp-sa-bigtable.iam.gserviceaccount.com`) `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key.
3. Set `kms_key_name` on every `cluster` block in the instance — CMEK for Bigtable can only be configured at cluster creation time and requires the `CLUSTER` display feature; it cannot be added retroactively to an existing cluster (you must create a new CMEK-enabled cluster and migrate data, e.g., via a Dataflow/backup-restore job).
4. Confirm your GCP project/region supports Bigtable CMEK (it is not available in all Bigtable regions).
5. Pair with `prevent_destroy` on the KMS key so the cluster's data isn't rendered permanently unreadable by an accidental key deletion.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/BigTableInstanceEncryptedWithCMK.py
- GCP docs: https://cloud.google.com/bigtable/docs/using-customer-managed-encryption-keys
