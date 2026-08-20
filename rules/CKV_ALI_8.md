# CKV_ALI_8: Ensure Disk is encrypted with Customer Master Key
## Severity
**LOW** (score: 2.0/10)

The disk is already required to be encrypted; using a platform-managed key instead of a customer-managed KMS key reduces key-rotation/revocation control but does not leave data unencrypted.

## Summary
This check ensures that an Alibaba Cloud ECS cloud disk (`alicloud_disk`) is not only encrypted, but encrypted specifically using a customer-managed KMS key (`kms_key_id`), rather than a platform-managed default key.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_disk`

## Why it matters
Basic encryption-at-rest (as validated by CKV_ALI_7) protects data if the storage medium is accessed directly, but if the encryption key itself is fully managed by the cloud provider, the customer has no independent control over key rotation, access auditing, or the ability to cryptographically revoke access to the data (e.g., by disabling the key). Using a Customer Master Key gives the data owner authoritative control: they decide who may use the key (via KMS access policies), can audit every encrypt/decrypt operation through KMS logs, and can immediately disable/delete the key to render the disk's data permanently inaccessible if a breach is suspected. For disks holding sensitive workloads, this level of key ownership is often a compliance or contractual requirement (customer-managed-key / BYOK mandates) and materially reduces reliance on the trust boundary of the cloud provider's own default key infrastructure.

## How Checkov evaluates this
This is a custom Python `BaseResourceCheck` for `alicloud_disk`:
- If `snapshot_id` is set, the result is **UNKNOWN** (encryption/key status is inherited from the source snapshot and cannot be statically determined).
- Otherwise: **PASS** only if `encrypted == [True]` AND `kms_key_id` is also set (non-empty).
- **FAIL** if `encrypted` is not `true`, or if it is `true` but no `kms_key_id` is specified (meaning the platform default key is used instead of a CMK).

## Non-compliant example
```hcl
resource "alicloud_disk" "example" {
  availability_zone = "cn-hangzhou-b"
  category          = "cloud_ssd"
  size              = 100
  encrypted         = true
  # kms_key_id not set -> uses the platform-managed default key
}
```

## Remediated example
```hcl
resource "alicloud_disk" "example" {
  availability_zone = "cn-hangzhou-b"
  category          = "cloud_ssd"
  size              = 100
  encrypted         = true
  kms_key_id        = alicloud_kms_key.example.id  # <-- added: uses a customer-managed KMS key
}
```

## Remediation steps
1. Provision (or reference) an `alicloud_kms_key` resource dedicated to disk encryption.
2. Set both `encrypted = true` and `kms_key_id = <your CMK ID>` on the `alicloud_disk` resource.
3. Define a restrictive KMS key policy limiting which principals may use the key, and enable automatic key rotation per your organization's standards.
4. As with CKV_ALI_7, changing the key used for an existing disk generally requires creating a new disk with the CMK and migrating data — this is not an in-place update.
5. For disks created from snapshots, verify and remediate the encryption/key configuration of the source snapshot, since this check reports `UNKNOWN` (not a pass) in that case.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/DiskEncryptedWithCMK.py)
