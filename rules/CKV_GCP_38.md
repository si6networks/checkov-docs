# CKV_GCP_38: Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK) [boot disk]

## Severity
**HIGH** (score: 7.5/10)

Same underlying risk as CSEK-on-disk (CKV_GCP_37) applied to the instance resource: lacking customer-managed encryption keys for critical VM disks reduces control over data-at-rest protection without leaving data fully unencrypted.

## Summary
This check requires the `boot_disk` block of a `google_compute_instance` to set either `disk_encryption_key_raw` or `kms_key_self_link`, ensuring the instance's boot disk — not just its data disks — is encrypted with a customer-supplied or customer-managed key.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to the `google_compute_instance` resource (specifically its `boot_disk` block).

## Why it matters
The boot disk holds the operating system, application binaries, configuration, and often cached credentials or secrets baked into the image — arguably the most sensitive disk attached to an instance. If the boot disk relies solely on Google-managed default encryption, anyone with sufficient GCP-internal access or an over-privileged IAM binding within the project can access disk contents (e.g., via a snapshot, disk clone, or direct disk read) without needing any key you control. Using a CMEK/CSEK (Cloud KMS-backed or raw customer key) on the boot disk ensures that decrypting it always requires presenting your own key, giving you a hard dependency that lets you immediately revoke access (by disabling/destroying the KMS key) and satisfies compliance requirements for customer key custody on the most sensitive volume of the VM.

## How Checkov evaluates this
The check inspects the `boot_disk` block:
- **PASS** if `boot_disk[0].disk_encryption_key_raw` is set and non-null, OR `boot_disk[0].kms_key_self_link` is set and non-null.
- **FAIL** if `boot_disk` is absent, or present but neither of those two fields is set.

## Non-compliant example
```hcl
resource "google_compute_instance" "app" {
  name         = "app-server"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }
}
```

## Remediated example
```hcl
resource "google_kms_crypto_key" "boot_disk_key" {
  name            = "boot-disk-key"
  key_ring        = google_kms_key_ring.instances.id
  rotation_period = "7776000s" # 90 days
}

resource "google_compute_instance" "app" {
  name         = "app-server"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
    kms_key_self_link     = google_kms_crypto_key.boot_disk_key.id
  }

  network_interface {
    network = "default"
  }
}
```

## Remediation steps
1. Add `kms_key_self_link` (recommended, Cloud KMS-backed — supports rotation and centralized IAM) or `disk_encryption_key_raw` (raw base64 AES-256 key) to the `boot_disk` block.
2. Grant the Compute Engine service agent (`service-PROJECT_NUMBER@compute-system.iam.gserviceaccount.com`) the `roles/cloudkms.cryptoKeyEncrypterDecrypter` role on the KMS key.
3. `kms_key_self_link` / `disk_encryption_key_raw` can only be set at instance/disk creation time — adding it to an existing instance forces replacement of the instance (new boot disk), so plan for a maintenance window or apply it going forward to new instances/modules.
4. Pair with CKV_GCP_43 to ensure the KMS key itself has automatic rotation enabled.
5. If the instances in question (`tailscale-relay-gcp`, `dev-vm`) are non-critical/ephemeral, evaluate whether the "critical VM" classification actually applies before investing in CSEK — otherwise add a documented Checkov suppression.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeBootDiskEncryption.py)
- [GCP: Customer-supplied encryption keys](https://cloud.google.com/compute/docs/disks/customer-supplied-encryption)
- [GCP: Protecting resources with Cloud KMS keys](https://cloud.google.com/compute/docs/disks/customer-managed-encryption)
