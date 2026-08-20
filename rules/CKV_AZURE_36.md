# CKV_AZURE_36: Ensure 'Trusted Microsoft Services' is enabled for Storage Account access

## Severity
**LOW** (score: 2.0/10)

This check governs whether trusted first-party Azure services can bypass storage network rules for legitimate platform integrations, so failing it is an operational/compatibility gap rather than a direct path to unauthorized data access.

## Summary
This check verifies that when a Storage Account's network rules default to denying traffic, the "Trusted Microsoft Services" bypass is enabled (or the default action is `Allow`), so first-party Azure services can still reach the account without requiring the whole default action to be opened up.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_storage_account` (inline `network_rules`) and `azurerm_storage_account_network_rules`
- **ARM templates**: `Microsoft.Storage/storageAccounts`
- **Bicep**: `Microsoft.Storage/storageAccounts`

## Why it matters
Many native Azure services (Azure Backup, Azure Site Recovery, Azure Monitor/diagnostic settings, Azure Event Grid, logging pipelines, etc.) need to write to or read from storage accounts, but they don't originate from a fixed, allow-list-able IP range. If a team locks down a storage account with `default_action = Deny` but forgets to enable the "AzureServices" bypass, they are forced to either (a) open the account back up broadly (defeating the point of network restriction) or (b) break legitimate platform integrations like backups and diagnostics logging. This check ensures teams get the benefit of network-level restriction on Deny defaults *without* silently breaking trusted first-party integrations, and conversely flags configurations where restriction is enabled but the bypass is explicitly excluded (`bypass = "None"`), which usually indicates a misconfiguration.

## How Checkov evaluates this
- **ARM**: Reads `properties.networkAcls`. FAIL if `apiVersion` predates 2017 (no networkAcls support). Otherwise PASS if `defaultAction == "Allow"` (no restriction, so bypass is moot) OR if `bypass` contains `"AzureServices"`. Otherwise FAIL.
- **Bicep**: PASS by default unless `defaultAction == "Deny"` AND `bypass` is empty or `"None"` — in which case it FAILs.
- **Terraform**: Looks at the `network_rules` block. If there's no `default_action` at all, PASSES (no restrictions applied). If `default_action == "Allow"`, PASSES. If `default_action == "Deny"` and a `bypass` value is set containing `"AzureServices"`, PASSES; otherwise FAILS.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action = "Deny"
    bypass          = ["None"]
  }
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

  network_rules {
    default_action = "Deny"
    bypass          = ["AzureServices"]
  }
}
```

## Remediation steps
1. Locate the `network_rules` block on the storage account (or the standalone `azurerm_storage_account_network_rules` resource).
2. If `default_action = "Deny"` is set, add `bypass = ["AzureServices"]` (Terraform accepts a list and may combine with `"Logging"`, `"Metrics"`).
3. In ARM/Bicep JSON, set `properties.networkAcls.bypass` to `"AzureServices"` (comma-separated string for multiple values, e.g. `"AzureServices, Logging"`).
4. Re-verify that platform integrations (Backup, Monitor diagnostic settings, Site Recovery) still function after applying the change.
5. Do not use this bypass as a substitute for narrowing `ip_rules`/`virtual_network_subnet_ids` — it only affects first-party Azure service traffic, not arbitrary external clients.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/StorageAccountAzureServicesAccessEnabled.py)
- [Checkov check source (Bicep)](https://github.com/bridgecrewio/checkov/blob/main/checkov/bicep/checks/resource/azure/StorageAccountAzureServicesAccessEnabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountAzureServicesAccessEnabled.py)
- [Azure Storage network rules - trusted Microsoft services](https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security#grant-access-to-trusted-azure-services)
