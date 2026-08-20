# CKV_NCP_14: Ensure NAS is securely encrypted

## Severity
**HIGH** (score: 7.5/10)

An NCP NAS volume without encryption enabled stores data at rest in plaintext, exposing its contents to anyone who gains access to the underlying storage or backup media.

## Summary
This check ensures that Naver Cloud Platform (NCP) Network Attached Storage volumes (`ncloud_nas_volume`) have encryption at rest enabled via the `is_encrypted_volume` attribute.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ncloud_nas_volume`
- **Check type:** resource-configuration attribute check

## Why it matters
NAS volumes commonly hold shared application data, backups, logs, and user-uploaded content across multiple compute instances. If the underlying storage is not encrypted at rest, anyone who gains access to the physical disks, storage snapshots, or improperly decommissioned/recycled storage media could read the raw data directly, bypassing any application-layer access controls entirely. This is particularly risky for shared storage because it often aggregates data from many services/tenants in one place, making it a high-value target. Encryption at rest ensures that even if the underlying storage medium is compromised, exfiltrated, or improperly disposed of, the data remains unreadable without the encryption keys — a baseline control required by most compliance frameworks (PCI-DSS, HIPAA, SOC 2, ISO 27001) for storage holding sensitive data.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `is_encrypted_volume` attribute of the `ncloud_nas_volume` resource. No custom expected value is overridden, so it uses the base class default, which requires the value to be truthy (`true`). If `is_encrypted_volume` is absent or set to `false`, the check **FAILS**. If it is set to `true`, the check **PASSES**.

## Non-compliant example
```hcl
resource "ncloud_nas_volume" "shared_data" {
  volume_name_postfix = "app-data"
  volume_size          = 500
  volume_allotment_protocol_type = "NFS"
  is_encrypted_volume  = false
}
```

## Remediated example
```hcl
resource "ncloud_nas_volume" "shared_data" {
  volume_name_postfix = "app-data"
  volume_size          = 500
  volume_allotment_protocol_type = "NFS"
  is_encrypted_volume  = true
}
```

## Remediation steps
1. Set `is_encrypted_volume = true` on every `ncloud_nas_volume` resource.
2. Be aware that encryption settings on NAS volumes are typically fixed at creation time — changing an existing unencrypted volume to encrypted usually requires provisioning a new encrypted volume and migrating data, rather than an in-place update. Plan for a maintenance window and data-migration/cutover process.
3. Update backup and DR procedures to snapshot/restore the encrypted volume correctly.
4. Verify performance characteristics after enabling encryption if the workload is I/O sensitive, though NCP-managed encryption is generally near-zero overhead.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/NASEncryptionEnabled.py)
- [Naver Cloud Terraform provider: ncloud_nas_volume](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/nas_volume)
