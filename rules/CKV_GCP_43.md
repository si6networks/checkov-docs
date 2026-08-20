# CKV_GCP_43: Ensure KMS encryption keys are rotated within a period of 90 days

## Severity
**LOW** (score: 2.0/10)

Failing to rotate KMS keys within 90 days increases the exposure window if a key is ever compromised, but does not itself expose data or grant access, making it a hygiene/defense-in-depth gap rather than a direct vulnerability.

## Summary
This check requires a `google_kms_crypto_key` resource to define a `rotation_period` between 1 and 90 days, ensuring symmetric encryption keys are rotated automatically on a bounded schedule.

## Applicability
Terraform only. Applies to the `google_kms_crypto_key` resource.

## Why it matters
Cryptographic key rotation limits the "blast radius" of key compromise over time: the longer a single key version is used to encrypt data, the more ciphertext accumulates under that one key, and the longer a leaked or brute-forced key remains useful to an attacker. Regular rotation (an industry and compliance-standard practice, e.g., PCI-DSS, NIST SP 800-57) bounds how much data any single compromised key version can decrypt, and reduces the incentive/value of attacking a specific key version since it will be retired regardless. Cloud KMS handles rotation by automatically generating a new primary key version on the configured schedule while retaining old versions for decrypting previously-encrypted data, so setting `rotation_period` is low-cost but meaningfully reduces long-term cryptographic exposure — especially important for encryption keys protecting persistent, long-lived data like disk encryption or database-at-rest encryption.

## How Checkov evaluates this
The check first excludes asymmetric keys: if `purpose` is `ASYMMETRIC_DECRYPT` or `ASYMMETRIC_SIGN`, the result is **UNKNOWN**, since GCP does not support automatic rotation for asymmetric keys at all.
For symmetric keys, it reads `rotation_period` (a duration string like `"7776000s"`, seconds-suffixed):
- **PASS** if the numeric portion (parsed by stripping the trailing unit character and converting to int) is between `ONE_DAY` (86400) and `NINETY_DAYS` (7,776,000) seconds, inclusive.
- **FAIL** if `rotation_period` is absent, not a string, unparsable, or outside that 1–90 day range (e.g., set to 180 days, or omitted entirely leaving the key never automatically rotated).

## Non-compliant example
```hcl
resource "google_kms_key_ring" "keyring" {
  name     = "app-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "key" {
  name     = "app-encryption-key"
  key_ring = google_kms_key_ring.keyring.id
  purpose  = "ENCRYPT_DECRYPT"
  # no rotation_period -> key is never automatically rotated
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "keyring" {
  name     = "app-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "key" {
  name            = "app-encryption-key"
  key_ring        = google_kms_key_ring.keyring.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s" # 90 days
}
```

## Remediation steps
1. Add `rotation_period` to the `google_kms_crypto_key` resource, expressed in seconds with an `s` suffix, set to a value between `86400s` (1 day) and `7776000s` (90 days) — commonly `7776000s` (90 days) or shorter for higher-sensitivity keys.
2. For asymmetric keys (`purpose = "ASYMMETRIC_DECRYPT"` or `"ASYMMETRIC_SIGN"`), automatic rotation isn't supported by GCP; instead implement manual key versioning/rotation procedures and document the compensating control, since Checkov will report `UNKNOWN` (not PASS) for these.
3. Since our finding is in a vendored external module (`terraform-google-kms`), set the `rotation_period` variable when calling the module rather than editing the vendored source directly, so the fix survives module updates.
4. Note: rotation creates a new key *version* under the same key resource — existing ciphertext remains decryptable via older versions, so this does not require re-encrypting existing data, though you should periodically re-encrypt if you want to fully retire old key material.
5. Confirm the KMS key's IAM bindings grant the necessary service agents `cloudkms.cryptoKeyEncrypterDecrypter` so consumers continue to work against the new primary version after rotation.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleKMSRotationPeriod.py)
- [GCP: Rotating Cloud KMS keys](https://cloud.google.com/kms/docs/key-rotation)
