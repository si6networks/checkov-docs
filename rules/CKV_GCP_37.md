# CKV_GCP_37: Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK)

## Severity
**LOW** (score: 2.0/10)

Without customer-supplied encryption keys, disk data for sensitive workloads relies solely on Google-managed keys, reducing the customer's cryptographic control over data-at-rest for critical VMs but still leaving data encrypted by default.

## Summary
This check requires a `google_compute_disk` resource to set the `disk_encryption_key` attribute, meaning the disk is encrypted using a key you supply rather than relying solely on Google's default encryption-at-rest.

## Applicability
Terraform only. Applies to the `google_compute_disk` resource.

## Why it matters
GCP encrypts all persistent disk data at rest by default using Google-managed keys, which protects against physical media theft but means Google (and anyone with sufficient access to Google-managed key infrastructure or an over-privileged IAM role in your project) can technically access the underlying data without needing a key you control. For workloads with strict data-sovereignty, compliance (e.g., regulated data, contractual key-custody requirements), or defense-in-depth requirements, relying only on default encryption leaves you without cryptographic separation of duties — anyone who can attach/read the disk within GCP's control plane can read its contents. Customer-Supplied Encryption Keys (CSEK) require the caller to present the key on every disk-attach/read operation; without it, Google itself cannot decrypt the disk. This means a compromised or overly broad IAM policy within your project cannot silently exfiltrate disk contents without also obtaining the out-of-band key, and it satisfies compliance regimes that require customer-held key custody.

## How Checkov evaluates this
The check requires the `disk_encryption_key` key to be present with any non-null value (`ANY_VALUE` sentinel):
- **PASS** if `disk_encryption_key` is set (to a CSEK config block, e.g. referencing a raw key or a Cloud KMS key).
- **FAIL** if `disk_encryption_key` is absent.

## Non-compliant example
```hcl
resource "google_compute_disk" "data" {
  name  = "critical-data-disk"
  type  = "pd-ssd"
  zone  = "us-central1-a"
  size  = 100
}
```

## Remediated example
```hcl
resource "google_compute_disk" "data" {
  name  = "critical-data-disk"
  type  = "pd-ssd"
  zone  = "us-central1-a"
  size  = 100

  disk_encryption_key {
    kms_key_self_link = google_kms_crypto_key.disk_key.id
  }
}
```

## Remediation steps
1. Add a `disk_encryption_key` block to the `google_compute_disk` resource, referencing either a raw base64 AES-256 key (`raw_key`) or, preferably, a Cloud KMS key (`kms_key_self_link`) so key rotation and access control are centrally managed.
2. Grant the Compute Engine service agent the `roles/cloudkms.cryptoKeyEncrypterDecrypter` role on the referenced KMS key so GCP can wrap/unwrap the disk's DEK.
3. Note that `disk_encryption_key` can only be set at disk-creation time — changing it on an existing disk forces resource replacement (data migration required); plan this for new critical-VM disks or during a planned migration window.
4. Combine with CKV_GCP_38 (boot disk encryption on the instance) and CKV_GCP_43 (KMS key rotation) for complete coverage of both data and boot disks.
5. Store any raw CSEK keys outside of Terraform state/version control (e.g., in Secret Manager) if not using KMS-backed keys, to avoid leaking the key material itself.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeDiskEncryption.py)
- [GCP: Customer-supplied encryption keys](https://cloud.google.com/compute/docs/disks/customer-supplied-encryption)
