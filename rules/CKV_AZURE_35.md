# CKV_AZURE_35: Ensure default network access rule for Storage Accounts is set to deny

## Severity
**HIGH** (score: 7.5/10)

Leaving the storage account's default network action at Allow exposes blob/file/queue/table data over the public internet to any caller that obtains a valid key or SAS token, removing the network layer as a defense against credential leakage or misuse.

## Summary
This check verifies that an Azure Storage Account's network rule set defaults to denying traffic, so that only explicitly allowed networks (VNets, IP ranges, or trusted Azure services) can reach the account.

## Applicability
- **Terraform**: `azurerm_storage_account` (inline `network_rules` block) and `azurerm_storage_account_network_rules` (standalone resource)
- **ARM templates**: `Microsoft.Storage/storageAccounts`
- **Bicep**: `Microsoft.Storage/storageAccounts`

## Why it matters
By default, an Azure Storage Account is reachable from any public IP address on the internet as long as the caller has valid credentials (account key, SAS token, or Azure AD auth). Setting the network default action to `Allow` removes network-layer defense-in-depth: a leaked SAS token or key becomes immediately exploitable from anywhere, and there's no way to scope access to trusted networks (corporate VPN ranges, peered VNets, specific service endpoints). Setting the default action to `Deny` forces an explicit allow-list, so compromised credentials alone are not sufficient to exfiltrate or tamper with blobs/queues/tables — the request must also originate from an approved network path. This is a foundational control for any storage account holding sensitive or regulated data.

## How Checkov evaluates this
- **Terraform**: The check looks at the `network_rules` block (inline in `azurerm_storage_account`, or the whole config for the standalone `azurerm_storage_account_network_rules` resource). It inspects `default_action`. If `default_action == "Deny"`, PASS. If it's present but not `"Deny"` (e.g. `"Allow"`), FAIL. If no `network_rules` block exists at all, the result is `UNKNOWN` for `azurerm_storage_account_network_rules` — but note the account-level default network posture then depends entirely on whether a rules block is configured.
- **ARM/Bicep**: Looks at `properties.networkAcls.defaultAction`. Additionally, for ARM the check fails outright if `apiVersion` is older than 2017 (network ACLs weren't configurable then). PASS only if `defaultAction == "Deny"`.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action = "Allow"
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
    default_action             = "Deny"
    ip_rules                   = ["203.0.113.0/24"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
    bypass                     = ["AzureServices"]
  }
}
```

## Remediation steps
1. Add (or update) a `network_rules` block on the `azurerm_storage_account` resource, or a separate `azurerm_storage_account_network_rules` resource pointing at the storage account.
2. Set `default_action = "Deny"`.
3. Enumerate the specific `ip_rules` and/or `virtual_network_subnet_ids` that legitimately need access.
4. If Azure platform services (Azure Backup, Azure Monitor diagnostics, etc.) need access, add `bypass = ["AzureServices"]` rather than opening the default action.
5. Test connectivity from all legitimate clients before rolling this out broadly — changing default action to Deny is a breaking change for any client not covered by an allow rule.
6. In ARM/Bicep templates, ensure `apiVersion` is 2017 or later so `networkAcls` is even a valid property.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/StorageAccountDefaultNetworkAccessDeny.py)
- [Checkov check source (Bicep)](https://github.com/bridgecrewio/checkov/blob/main/checkov/bicep/checks/resource/azure/StorageAccountDefaultNetworkAccessDeny.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountDefaultNetworkAccessDeny.py)
- [Azure Storage networking documentation](https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security)
