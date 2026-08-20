# CKV_ALI_27: Ensure KMS Key Rotation is enabled
## Severity
**LOW** (score: 2.0/10)

Disabled automatic KMS key rotation means a single key material stays in use indefinitely, increasing the impact if that key is ever compromised, though the key itself remains protected by KMS access controls.

## Summary
This check verifies that automatic key rotation is enabled on Alibaba Cloud KMS (Key Management Service) keys.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `alicloud_kms_key`

## Why it matters
A KMS key that is never rotated means a single cryptographic key material version protects data indefinitely. If that key material is ever compromised — through an insider threat, a misconfiguration, or a vulnerability in a system that had access to use the key — every piece of data ever encrypted with it remains at risk for as long as the key exists, with no natural boundary limiting the blast radius. Automatic key rotation periodically generates new key material (while KMS transparently retains prior versions to decrypt older ciphertext), which limits the amount of data protected by any single key version and reduces the value of a compromised key to an attacker, without requiring any application-level re-encryption effort.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` on `alicloud_kms_key` with `missing_block_result=CheckResult.FAILED`:
- Inspects the `automatic_rotation` attribute.
- FAILS if the resource/attribute is missing, or if `automatic_rotation` is not `"Enabled"`.
- PASSES only if `automatic_rotation = "Enabled"`.

## Non-compliant example
```hcl
resource "alicloud_kms_key" "example" {
  description            = "example encryption key"
  pending_window_in_days = 7
  status                 = "Enabled"
  automatic_rotation      = "Disabled"   # <-- fails: key rotation not enabled
}
```

## Remediated example
```hcl
resource "alicloud_kms_key" "example" {
  description            = "example encryption key"
  pending_window_in_days = 7
  status                 = "Enabled"
  automatic_rotation      = "Enabled"    # <-- fix: automatic key rotation enabled
}
```

## Remediation steps
1. Locate any `alicloud_kms_key` resource without `automatic_rotation = "Enabled"`.
2. Add or update `automatic_rotation = "Enabled"`.
3. Confirm the key type supports rotation — Alibaba Cloud KMS automatic rotation is supported for Aliyun_AES_256 (symmetric, default origin) keys; keys with externally imported key material or certain asymmetric key specs may not support automatic rotation, in which case a manual rotation process should be documented instead.
4. This is generally an in-place, non-disruptive change; existing ciphertext remains decryptable through key version tracking that KMS manages transparently.
5. Review your default rotation period (Alibaba Cloud KMS typically rotates annually once enabled) and confirm it meets your organization's key-management policy.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/KMSKeyRotationIsEnabled.py)
- [Alibaba Cloud KMS key resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/kms_key)
