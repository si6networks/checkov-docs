# CKV_AZURE_58: Ensure that Azure Synapse workspaces enables managed virtual networks
## Severity
**LOW** (score: 2.0/10)

Skipping Synapse's managed virtual network leaves data-plane traffic to linked sources traversing public network paths instead of isolated private endpoints, weakening network segmentation around a typically high-value analytics workload.

## Summary
This check fails when an Azure Synapse Analytics workspace does not have managed virtual network isolation enabled, leaving Spark pools and integration runtimes without the platform-managed network boundary.

## Applicability
Applies to Terraform (`azurerm_synapse_workspace`), ARM templates, and Bicep, for the resource type `Microsoft.Synapse/workspaces`.

## Why it matters
A Synapse managed virtual network provisions a dedicated, Microsoft-managed VNet for the workspace's Spark pools and Azure Integration Runtime, and enables managed private endpoints so data-plane traffic to linked data sources doesn't need to traverse the public internet. Without it, Synapse compute nodes rely on public network paths to reach data sources and can be exposed to lateral movement between different workspaces/tenants sharing default network infrastructure, as well as to data exfiltration paths through public endpoints. Since Synapse workspaces often hold aggregated, highly sensitive data (this is frequently the crown-jewel analytics layer of an organization), skipping network isolation increases both the blast radius of a compromised pool and the feasibility of unauthorized egress of query results to attacker-controlled endpoints.

## How Checkov evaluates this
- ARM/Bicep: reads `properties/managedVirtualNetwork` and FAILS if its value equals the forbidden value `"default"` (i.e., disabled/default networking); any other value (e.g. an actual managed VNet name) PASSES.
- Terraform: reads the `managed_virtual_network_enabled` attribute on `azurerm_synapse_workspace` and expects it to be truthy; if unset (provider default `false`) or explicitly `false`, FAILS.

## Non-compliant example
```hcl
resource "azurerm_synapse_workspace" "example" {
  name                                 = "example-synapse"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = var.sql_admin_password

  # managed_virtual_network_enabled omitted (defaults to false)
}
```

## Remediated example
```hcl
resource "azurerm_synapse_workspace" "example" {
  name                                 = "example-synapse"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = var.sql_admin_password

  managed_virtual_network_enabled = true  # isolates Spark pools / IR in a managed VNet
}
```

## Remediation steps
1. Set `managed_virtual_network_enabled = true` on the `azurerm_synapse_workspace` resource (or `properties.managedVirtualNetwork` to a non-"default" value in ARM/Bicep).
2. Note that managed virtual network can only be set at workspace creation time — enabling it on an existing workspace requires recreating the workspace (Terraform will need to replace the resource).
3. Once enabled, configure managed private endpoints (`azurerm_synapse_managed_private_endpoint`) for each linked data source (storage accounts, SQL, Key Vault, etc.) so integration runtimes route privately.
4. Consider also setting `managed_resource_group_name` and restricting outbound access via a data exfiltration protection policy if handling highly sensitive data.
5. Plan for a maintenance window since this is a replacement operation, not an in-place update.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SynapseWorkspaceEnablesManagedVirtualNetworks.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SynapseWorkspaceEnablesManagedVirtualNetworks.py)
- [Azure docs: Synapse managed virtual network](https://learn.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-vnet)
