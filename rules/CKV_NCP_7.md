# CKV_NCP_7: Ensure Basic Block storage is encrypted
## Severity
**HIGH** (score: 7.0/10)

An unencrypted Basic Block Storage volume provisioned via the launch configuration leaves instance data at rest unprotected, exposing it to disclosure if the underlying storage is accessed outside the running instance.

## Summary
This check requires that an NCloud `ncloud_launch_configuration` resource (used by auto-scaling groups) has its attached block storage volume encrypted (`is_encrypted_volume = true`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ncloud_launch_configuration`
- **Check type:** resource (single attribute value check)

## Why it matters
A launch configuration defines the template instances launched by an auto-scaling group will use, including their storage volumes. If the block storage volume in that template is not encrypted, every instance the auto-scaling group spins up inherits an unencrypted disk holding the OS, application data, and any locally cached data or secrets. Unencrypted volumes are readable in plaintext from the underlying storage medium, from any snapshot taken of the volume, or from a backup — exposing sensitive data to anyone who can access those artifacts outside the normal instance authentication path (e.g., via a leaked/misconfigured snapshot, storage-layer breach, or improper decommissioning). Because auto-scaling groups can create many instances automatically and repeatedly, a missed encryption setting here silently propagates the exposure to every instance the group ever launches.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` that inspects the `is_encrypted_volume` attribute of `ncloud_launch_configuration`:
- No explicit `get_expected_value()` is overridden, so the base class default expected value of `True` applies.
- **PASS:** `is_encrypted_volume = true`.
- **FAIL:** the attribute is `false`, or is not set at all.

## Non-compliant example
```hcl
resource "ncloud_launch_configuration" "app_lc" {
  name                       = "app-launch-config"
  server_image_product_code  = "SW.VSVR.OS.LNX64.CNTOS.0708.B050"
  server_product_code        = "SVR.VSVR.STAND.C002.M008.NET.SSD.B050.G002"
  login_key_name             = "app-key"
}
```

## Remediated example
```hcl
resource "ncloud_launch_configuration" "app_lc" {
  name                       = "app-launch-config"
  server_image_product_code  = "SW.VSVR.OS.LNX64.CNTOS.0708.B050"
  server_product_code        = "SVR.VSVR.STAND.C002.M008.NET.SSD.B050.G002"
  login_key_name             = "app-key"
  is_encrypted_volume        = true
}
```

## Remediation steps
1. Add `is_encrypted_volume = true` to every `ncloud_launch_configuration` resource.
2. Because launch configurations are immutable in NCP/Terraform (any change typically forces creation of a new launch configuration), plan for the associated auto-scaling group to be updated to reference the new, encrypted launch configuration, and for existing instances to be replaced through the normal scaling/refresh process.
3. Confirm the server image and product code combination in use supports encrypted volumes in your target region.
4. Roll the change out via a new launch configuration + auto-scaling group update rather than attempting an in-place edit, to avoid unexpected instance termination.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/LaunchConfigurationEncryptionVPC.py)
