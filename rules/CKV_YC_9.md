# CKV_YC_9: Ensure KMS symmetric key is rotated.

## Severity
**MEDIUM** (score: 4.5/10)

Without a configured rotation period, a KMS symmetric key is used indefinitely, so a future key compromise would retroactively expose all data ever encrypted under that key rather than being time-bounded by rotation.

## Summary
This check ensures that a Yandex Cloud KMS symmetric key has a `rotation_period` configured, so the underlying cryptographic key material is automatically rotated on a schedule rather than remaining static indefinitely.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `yandex_kms_symmetric_key`
- **Check type:** resource (value check, `ANY_VALUE` expected)

## Why it matters
Cryptographic best practice holds that keys should not be used indefinitely: the longer a key remains in use, the larger the volume of ciphertext protected by it, and the greater the impact if that key material is ever compromised (via insider misuse, a vulnerability in a system with decrypt access, or a supply-chain compromise of a service holding the key). Automatic key rotation limits the "blast radius" of a potential key compromise — an attacker who obtains an old key version can only decrypt data encrypted under that specific version, not the entire history or future of ciphertext, once rotation is in effect and new data is encrypted under fresh key material. Regular rotation is also a common compliance requirement (PCI-DSS, SOC 2, ISO 27001, various government/financial regulations) and is considered a cryptographic hygiene control akin to password rotation, reducing the useful lifetime of any single key version to attackers who might obtain it through cryptanalysis, insider threat, or improper access-control drift over time. Without a configured `rotation_period`, the key's material is never automatically rotated by the platform.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `rotation_period` attribute directly on the `yandex_kms_symmetric_key` resource. The expected value is `ANY_VALUE`, meaning the check **PASSES** as soon as `rotation_period` is set to any value (e.g., `"8760h"` for a yearly rotation). If `rotation_period` is omitted entirely, the check **FAILS**.

## Non-compliant example
```hcl
resource "yandex_kms_symmetric_key" "bad_example" {
  name              = "app-data-key"
  default_algorithm = "AES_256"
  # No rotation_period set — key material is never rotated
}
```

## Remediated example
```hcl
resource "yandex_kms_symmetric_key" "good_example" {
  name              = "app-data-key"
  default_algorithm = "AES_256"
  # Rotation period added: key material rotates automatically every year
  rotation_period   = "8760h"
}
```

## Remediation steps
1. Add a `rotation_period` attribute to the `yandex_kms_symmetric_key` resource, expressed as a duration string (e.g., `"8760h"` for one year, `"4380h"` for six months).
2. Choose a rotation cadence aligned with your organization's compliance requirements and risk tolerance — shorter periods reduce blast radius but increase key management overhead.
3. Confirm that services decrypting data with this key use the KMS API (rather than caching raw key material locally), since Yandex KMS transparently manages multiple key versions so older ciphertext remains decryptable after rotation without any application changes.
4. Note that enabling rotation on an existing key does not re-encrypt already-encrypted data; only new encryption operations after rotation use the new key version — for full defense-in-depth, consider a data re-encryption strategy on a periodic basis for highly sensitive datasets.
5. Re-run Checkov to confirm `rotation_period` is present on the resource.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/KMSSymmetricKeyRotation.py
