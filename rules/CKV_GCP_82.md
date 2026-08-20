# CKV_GCP_82: Ensure KMS keys are protected from deletion
## Severity
**LOW** (score: 2.0/10)

This guards against irrecoverable data loss from accidental key destruction (an availability/integrity failure), not a direct confidentiality breach, since it only fires when prevent_destroy is absent from a Terraform lifecycle block.

## Summary
This check verifies that Terraform `google_kms_crypto_key` resources have a `lifecycle` block with `prevent_destroy = true`, so that a `terraform destroy`/`terraform apply` cannot silently disable the key.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_kms_crypto_key`
- **Check type:** resource (attribute-value check)

## Why it matters
Google Cloud KMS `CryptoKey` resources cannot be truly deleted from the platform via the API — Google enforces this deliberately so that data encrypted under a key can always, in principle, be recovered as long as the key material and its versions still exist. However, Terraform state manipulation is a different matter: if a `google_kms_crypto_key` resource is removed from a Terraform configuration (or the module block is deleted) and `terraform apply` runs without a `prevent_destroy` lifecycle guard, Terraform will disable the key resource and destroy every `CryptoKeyVersion` under it. Once every key version is destroyed, any ciphertext, disk, bucket, BigQuery table, or Secret Manager entry encrypted under that key becomes **permanently and irrecoverably unreadable** — this is effectively a self-inflicted, silent data-destruction event with no undo. Because this can happen from something as mundane as a bad merge, a rename that Terraform interprets as delete+recreate, or a careless `terraform state rm`, the `prevent_destroy` guard is the only safety net Terraform offers against this class of accident.

## How Checkov evaluates this
The check (`GoogleKMSPreventDestroy`, a `BaseResourceValueCheck`) inspects the attribute path `lifecycle/[0]/prevent_destroy` on every `google_kms_crypto_key` resource block.
- **PASS**: the resource has a `lifecycle { prevent_destroy = true }` block.
- **FAIL**: the `lifecycle` block is absent, or `prevent_destroy` is missing or set to `false`.

## Non-compliant example
```hcl
resource "google_kms_key_ring" "keyring" {
  name     = "app-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "key" {
  name            = "app-crypto-key"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "7776000s"
  # No lifecycle block -> destroy is not blocked
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "keyring" {
  name     = "app-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "key" {
  name            = "app-crypto-key"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = true
  }
}
```

## Remediation steps
1. Add a `lifecycle { prevent_destroy = true }` block to every `google_kms_crypto_key` resource.
2. If the key is created inside a shared module (as in the `terraform-google-kms` external module used here), confirm the module itself sets this, or wrap/fork the module to add it — module consumers usually cannot override a missing lifecycle block from the calling configuration.
3. Note that `lifecycle` arguments cannot use variables/interpolation in older Terraform versions; the value must be a literal `true`.
4. If you ever need to intentionally retire a key, you must first remove the `prevent_destroy` guard in a dedicated change, review it carefully, and only then destroy the resource — treat this as a deliberate, reviewed two-step operation, never a routine one.
5. This guard only protects against Terraform-driven destruction; it does not prevent manual deletion of key rings/keys via the GCP Console or `gcloud`, so pair it with IAM restrictions on `cloudkms.cryptoKeys.destroy an d cloudkms.cryptoKeyVersions.destroy`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleKMSPreventDestroy.py
- GCP docs: https://cloud.google.com/kms/docs/destroy-restore
