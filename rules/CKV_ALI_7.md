# CKV_ALI_7: Ensure disk is encrypted
## Severity
**LOW** (score: 2.0/10)

An unencrypted disk exposes all data written to it in plaintext to anyone who gains access to the underlying storage, snapshots, or backups.

## Summary
This check ensures that an Alibaba Cloud ECS cloud disk (`alicloud_disk`) has encryption enabled at rest.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_disk`

## Why it matters
An unencrypted block storage disk stores its data in cleartext on the underlying physical/virtual storage medium. If a snapshot of that disk is exported, shared with the wrong party, mounted onto a different instance, or the storage backend is otherwise accessed outside the normal instance boundary, the contents are immediately readable — with no additional barrier. This is particularly risky for disks that may contain application data, credentials, temp files, or database volumes. Disk-level encryption at rest is one of the most basic and widely mandated data-protection controls (required or strongly recommended under GDPR, HIPAA, PCI-DSS, and most cloud security benchmarks) precisely because it is cheap to enable and closes off an entire class of "storage-layer" data exposure that has nothing to do with application-level access controls.

## How Checkov evaluates this
This is a custom Python `BaseResourceCheck` for `alicloud_disk`:
- If `snapshot_id` is set (the disk is created from a snapshot), the result is **UNKNOWN** — Checkov cannot determine encryption status from static analysis alone, since it is inherited from the source snapshot.
- Otherwise, **PASS** only if `encrypted == [True]` (i.e., `encrypted = true` is explicitly set).
- **FAIL** in all other cases (attribute missing, or `encrypted = false`).

## Non-compliant example
```hcl
resource "alicloud_disk" "example" {
  availability_zone = "cn-hangzhou-b"
  category          = "cloud_ssd"
  size              = 100
  # "encrypted" not set -> disk is unencrypted
}
```

## Remediated example
```hcl
resource "alicloud_disk" "example" {
  availability_zone = "cn-hangzhou-b"
  category          = "cloud_ssd"
  size              = 100
  encrypted         = true  # <-- added: enables encryption at rest
}
```

## Remediation steps
1. Add `encrypted = true` to every `alicloud_disk` resource that is not created from an existing snapshot.
2. If the disk is created from a snapshot (`snapshot_id` set), verify the source snapshot's encryption status separately, since Checkov cannot infer it and marks such disks `UNKNOWN` rather than pass/fail.
3. Optionally set `kms_key_id` alongside `encrypted = true` to use a customer-managed key rather than the platform default key (see CKV_ALI_8).
4. Be aware: enabling encryption on an already-existing, unencrypted disk generally requires creating a new encrypted disk and migrating data — encryption cannot typically be toggled in place on a live disk.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/DiskIsEncrypted.py)
