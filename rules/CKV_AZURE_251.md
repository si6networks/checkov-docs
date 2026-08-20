# CKV_AZURE_251: Ensure Azure Virtual Machine disks are configured without public network access

## Severity
**HIGH** (score: 7.5/10)

A managed disk with public network access enabled can be exported wholesale via a SAS URL to anyone holding a valid token, exposing full disk contents including OS secrets and application data without any VNet-level access requirement.

## Summary
This check ensures that Azure managed disks (`azurerm_managed_disk`) explicitly disable public network access rather than allowing disk export/import endpoints to be reachable from the public internet.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `azurerm_managed_disk`

## Why it matters
Azure managed disks support "disk network access" settings that can expose a public endpoint used for direct disk export (e.g., generating a SAS URL to download the raw disk). If `public_network_access_enabled` is `true` — or simply left unset, since the check also fails when the attribute is absent — the disk can potentially be exported over a public endpoint, exposing full-disk contents (OS files, secrets baked into images, application data) to anyone who obtains a valid SAS token, without requiring network-level access to the VNet. Disabling public network access forces all disk export/access operations through private endpoints or Azure-internal paths, closing off a data-exfiltration channel that bypasses VNet/NSG controls entirely.

## How Checkov evaluates this
This is a `BaseResourceCheck`:
- **FAIL** if `public_network_access_enabled` is not set at all in the resource config.
- **FAIL** if `public_network_access_enabled` is `true` (checked as the string `"True"` or boolean `True` in the raw parsed config).
- **PASS** only if `public_network_access_enabled` is present and evaluates to `false`.

## Non-compliant example
```hcl
resource "azurerm_managed_disk" "example" {
  name                 = "example-disk"
  location             = "eastus"
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 128
  # public_network_access_enabled not set -> fails
}
```

## Remediated example
```hcl
resource "azurerm_managed_disk" "example" {
  name                 = "example-disk"
  location             = "eastus"
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 128

  public_network_access_enabled = false   # added
}
```

## Remediation steps
1. Add `public_network_access_enabled = false` to every `azurerm_managed_disk` resource — do not rely on the provider default.
2. If disk export is genuinely required (e.g., for forensics or migration), use a private endpoint (`network_access_policy = "AllowPrivate"` with a disk access resource) instead of enabling public access.
3. Requires `azurerm` provider version that supports the `public_network_access_enabled` argument on managed disks; verify before applying to older Terraform states.
4. Changing this setting on an existing disk does not require replacement, but confirm any existing export/SAS workflows are migrated to private endpoints first to avoid breaking them.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMDiskWithPublicAccess.py)
- [Azure managed disk network access controls](https://learn.microsoft.com/en-us/azure/virtual-machines/disks-enable-private-links-for-import-export-portal)
