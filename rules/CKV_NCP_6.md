# CKV_NCP_6: Ensure Server instance is encrypted
## Severity
**HIGH** (score: 7.0/10)

An unencrypted Server instance volume leaves data at rest unprotected, so anyone who gains access to the underlying storage or a snapshot can read the data directly.

## Summary
This check requires that an NCloud `ncloud_server` resource has its base block storage volume encrypted (`is_encrypted_base_block_storage_volume = true`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_server`
- **Check type:** resource (single attribute value check)

## Why it matters
The base block storage volume of a server instance typically holds the operating system, application code, configuration files, and potentially cached credentials or secrets. If that volume is not encrypted at rest, anyone who gains access to the underlying physical storage medium, a storage snapshot, or a backup copy — whether through a cloud provider security failure, an insider threat, improperly disposed hardware, or a misconfigured snapshot-sharing setting — can read the raw disk contents without needing to authenticate to the running instance at all. Encryption at rest ensures that data on the volume is unintelligible outside of the properly authorized decryption context, which is a baseline expectation for handling any sensitive workload and is required by many compliance frameworks (PCI-DSS, HIPAA, ISO 27001, etc.).

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` that inspects the `is_encrypted_base_block_storage_volume` attribute of `ncloud_server`:
- No explicit `get_expected_value()` is overridden, so the base class default expected value of `True` applies.
- **PASS:** `is_encrypted_base_block_storage_volume = true`.
- **FAIL:** the attribute is `false`, or is not set at all.

## Non-compliant example
```hcl
resource "ncloud_server" "app" {
  name                       = "app-server"
  server_image_product_code  = "SW.VSVR.OS.LNX64.CNTOS.0708.B050"
  server_product_code        = "SVR.VSVR.STAND.C002.M008.NET.SSD.B050.G002"
}
```

## Remediated example
```hcl
resource "ncloud_server" "app" {
  name                                    = "app-server"
  server_image_product_code               = "SW.VSVR.OS.LNX64.CNTOS.0708.B050"
  server_product_code                     = "SVR.VSVR.STAND.C002.M008.NET.SSD.B050.G002"
  is_encrypted_base_block_storage_volume  = true
}
```

## Remediation steps
1. Add `is_encrypted_base_block_storage_volume = true` to every `ncloud_server` resource definition.
2. Note that enabling encryption on the base block storage volume typically must be set at server creation time — changing this on an existing, already-provisioned server may require recreating the instance (resource replacement), so plan for a maintenance window or blue/green migration if applying to production servers retroactively.
3. Verify the chosen server image/product code combination supports encrypted base block storage in the target NCP region/zone before applying.
4. Pair this with encryption of any additional attached block storage volumes (see the related `ncloud_launch_configuration` encryption check) for full-disk coverage.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/ServerEncryptionVPC.py)
