# CKV2_GCP_27: Ensure Vertex AI workbench instance disks are encrypted with a Customer Managed Key (CMK)
## Severity
**MEDIUM** (score: 5.0/10)

Vertex AI workbench instance disks without a CMK still receive Google-managed encryption, so the exposure is reduced key-rotation/control assurance for notebook data rather than plaintext storage.

## Summary
This check ensures that a Vertex AI Workbench instance's boot disk (and any data disks, if present) are encrypted with a customer-managed KMS key rather than relying only on Google-managed default encryption.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_workbench_instance`

## Why it matters
Vertex AI Workbench instances are managed Jupyter notebook environments frequently used to explore datasets, prototype models, and store credentials/API keys locally on the instance disk. Both the boot disk and any attached data disks can hold sensitive source data, trained model checkpoints, or embedded secrets. Without CMEK on both disk types, the organization loses independent cryptographic control over that data — it cannot revoke access via key management alone, and gaps in coverage (e.g., encrypting the boot disk but not attached data disks) leave a partial, false sense of protection since a bulk of sensitive working data commonly lives on data disks. This check explicitly validates both disk locations to close that gap.

## How Checkov evaluates this
This is a Terraform graph-based check on `google_workbench_instance` requiring both of the following:
- `gce_setup.boot_disk.kms_key` exists (boot disk is CMEK-encrypted), **and**
- Either `gce_setup.data_disks` does not exist at all (no data disks configured), **or**, if data disks exist, `gce_setup.data_disks.kms_key` also exists.
**FAIL** occurs if the boot disk lacks a `kms_key`, or if data disks are configured but lack a `kms_key`.

## Non-compliant example
```hcl
resource "google_workbench_instance" "instance" {
  name     = "my-workbench"
  location = "us-central1-a"

  gce_setup {
    machine_type = "n1-standard-4"

    boot_disk {
      disk_size_gb = 150
      disk_type    = "PD_SSD"
      # no kms_key -> Google-managed encryption
    }

    data_disks {
      disk_size_gb = 100
      disk_type    = "PD_SSD"
      # no kms_key on data disk either
    }
  }
}
```

## Remediated example
```hcl
resource "google_workbench_instance" "instance" {
  name     = "my-workbench"
  location = "us-central1-a"

  gce_setup {
    machine_type = "n1-standard-4"

    boot_disk {
      disk_size_gb = 150
      disk_type    = "PD_SSD"
      kms_key      = google_kms_crypto_key.workbench_key.id
    }

    data_disks {
      disk_size_gb = 100
      disk_type    = "PD_SSD"
      kms_key      = google_kms_crypto_key.workbench_key.id
    }
  }
}

resource "google_kms_crypto_key" "workbench_key" {
  name     = "workbench-disk-key"
  key_ring = google_kms_key_ring.workbench_ring.id
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in the same zone/region as the Workbench instance.
2. Grant the Compute Engine service agent `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key.
3. Set `kms_key` inside both the `gce_setup.boot_disk` block AND every `gce_setup.data_disks` block.
4. Disk encryption settings are generally immutable after instance creation — applying this to an existing instance requires creating a new instance and migrating notebook content/data.
5. If you don't use data disks at all, ensure the block is fully omitted (not present with an empty/default config) so the "no data disks" pass condition applies cleanly.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPVertexWorkbenchInstanceEncryptedWithCMK.json
- GCP docs: https://cloud.google.com/vertex-ai/docs/workbench/instances/encryption
