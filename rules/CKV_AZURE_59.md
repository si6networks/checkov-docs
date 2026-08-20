# CKV_AZURE_59: Ensure that Storage accounts disallow public access
## Severity
**HIGH** (score: 7.5/10)

Allowing public network access to a storage account removes the network-layer barrier that protects against leaked SAS tokens or account keys, turning any future authorization mistake into an immediately internet-exploitable data exposure.

## Summary
This check fails when an Azure Storage Account has public network access enabled, meaning the storage account's data plane (blob/file/queue/table endpoints) is reachable from the public internet rather than being restricted to private/virtual network connectivity.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

Applies to Terraform (`azurerm_storage_account`), ARM templates, and Bicep, for the resource type `Microsoft.Storage/storageAccounts`.

## Why it matters
Storage accounts are one of the most common sources of real-world cloud data breaches — misconfigured public access (combined with anonymous blob access, weak SAS tokens, or leaked account keys) has repeatedly led to mass exposure of sensitive files, backups, and logs. Even when individual containers/blobs are set to private, leaving the account's public network access enabled means the account is still directly addressable from any IP on the internet, so any future container-level misconfiguration, a leaked SAS token, or an exploited access key immediately becomes internet-exploitable with no additional network barrier. Disabling public network access forces access to go only through private endpoints or explicitly allow-listed virtual networks/IP ranges, adding a network-layer control that is independent of (and defends against mistakes in) the storage account's own authorization configuration.

## How Checkov evaluates this
- ARM/Bicep: reads `properties/publicNetworkAccess` and FAILS if the value is the forbidden value `"Enabled"`. Any other value (e.g. `"Disabled"`) PASSES.
- Terraform: reads `public_network_access_enabled` on `azurerm_storage_account` and expects the value `false`; if set to `true` or left at the provider default (`true`), it FAILS.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  public_network_access_enabled = true
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  public_network_access_enabled = false  # only private endpoint / VNet access allowed
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess: "Disabled"` (ARM/Bicep).
2. Create a Private Endpoint (`azurerm_private_endpoint`) for each required subresource (`blob`, `file`, `queue`, `table`, `dfs`) so internal consumers can still reach the account privately.
3. If some public access is genuinely required temporarily, use `network_rules` with specific `ip_rules`/`virtual_network_subnet_ids` and `default_action = "Deny"` instead of leaving the account fully open — but note this check specifically requires `public_network_access_enabled = false`, which is stricter than network rules alone.
4. Update DNS to resolve through the appropriate Private DNS Zone (e.g. `privatelink.blob.core.windows.net`) so clients transparently use the private endpoint.
5. Test all consumers (apps, pipelines, CI/CD, third-party integrations) after the change — anything relying on public internet access to the account will break and must be migrated to use the VNet/private endpoint path.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/StorageAccountDisablePublicAccess.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountDisablePublicAccess.py)
- [Azure docs: Use private endpoints for Azure Storage](https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints)
