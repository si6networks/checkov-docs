# CKV_TC_1: Ensure Tencent Cloud CBS is encrypted

## Severity
**HIGH** (score: 7.0/10)

Unencrypted block storage exposes the raw contents of potentially sensitive application and database data to anyone who obtains the underlying disk, snapshot, or an unauthorized volume attach, bypassing all OS-level access controls.

## Summary
This check ensures that Tencent Cloud Block Storage (CBS) disks have encryption enabled at the storage layer.

## Applicability
Terraform, resource type `tencentcloud_cbs_storage` (Tencent Cloud provider).

## Why it matters
CBS volumes back the root and data disks of Tencent Cloud CVM instances and can contain sensitive data — application data, database files, credentials cached on disk, or snapshots taken for backup. Without encryption at rest, anyone who gains access to the underlying physical storage medium, a stolen/mishandled disk snapshot, or an unauthorized detach-and-attach of the volume to another instance can read the raw disk contents directly, bypassing OS-level access controls entirely. Enabling storage-level encryption ensures data is unreadable outside the scope of the managed key, protecting against these out-of-band access paths even when compute-layer controls (IAM, OS permissions) are otherwise sound.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `encrypt` attribute of a `tencentcloud_cbs_storage` resource. Checkov expects `encrypt` to be explicitly set to `true`. If `encrypt` is absent, `false`, or any value other than `true`, the check **FAILS**; when `encrypt = true` is set, the check **PASSES**.

## Non-compliant example
```hcl
resource "tencentcloud_cbs_storage" "example" {
  storage_name = "app-data-disk"
  storage_type = "CLOUD_SSD"
  storage_size = 100
  availability_zone = "ap-guangzhou-3"
  # encrypt not set -> defaults to unencrypted
}
```

## Remediated example
```hcl
resource "tencentcloud_cbs_storage" "example" {
  storage_name      = "app-data-disk"
  storage_type      = "CLOUD_SSD"
  storage_size      = 100
  availability_zone = "ap-guangzhou-3"
  encrypt           = true   # storage encryption enabled
}
```

## Remediation steps
1. Add `encrypt = true` to every `tencentcloud_cbs_storage` resource.
2. Note that `encrypt` typically cannot be toggled on an existing disk in place — enabling encryption on a previously unencrypted volume may require creating a new encrypted disk and migrating data (snapshot/restore), which requires planning a maintenance window.
3. Verify the CBS storage type and region support encryption (most current Tencent Cloud regions/types do, but confirm for older/legacy zones).
4. Apply this as a baseline in Terraform modules that provision CBS disks so future volumes default to encrypted.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/CBSEncryption.py
