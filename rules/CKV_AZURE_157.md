# CKV_AZURE_157: Ensure that Synapse workspace has data_exfiltration_protection_enabled

## Severity
**LOW** (score: 2.0/10)

Without data exfiltration protection, a Synapse workspace can send data to arbitrary external Azure tenants and endpoints, creating a direct path for sensitive analytics data to leave the organization's security boundary.

## Summary
This check ensures that an Azure Synapse Analytics workspace has data exfiltration protection enabled, which restricts outbound data movement to only approved (allow-listed) Azure tenants and destinations.

## Applicability
- **Frameworks:** Terraform, Bicep, ARM
- **Resource types:**
  - Terraform: `azurerm_synapse_workspace`
  - ARM/Bicep: `Microsoft.Synapse/workspaces`

## Why it matters
Synapse workspaces have broad connectivity to external data sources and sinks (storage accounts, databases, other Synapse workspaces) as part of their core data-integration functionality. Without data exfiltration protection, a malicious or compromised insider (e.g. a user with Synapse Studio access, or an attacker who has compromised a pipeline's credentials) could copy sensitive data out of the organization's Azure tenant to an external/unauthorized destination — effectively using Synapse's own legitimate data-movement capabilities as an exfiltration channel. Enabling this feature locks outbound connectivity down to an explicit allow-list of approved tenants, closing off that abuse path while still allowing normal, approved data flows.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Terraform:** inspects `data_exfiltration_protection_enabled` on `azurerm_synapse_workspace`.
- **ARM/Bicep:** inspects `properties.dataExfiltrationProtectionEnabled`.
- **PASS** if the value is `true`.
- **FAIL** if `false` or omitted (default missing-block behavior for `BaseResourceValueCheck` is FAILED).

## Non-compliant example
```hcl
resource "azurerm_synapse_workspace" "example" {
  name                                 = "example-synapse"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = "H@Sh1CoR3!"

  # data_exfiltration_protection_enabled omitted -> outbound data movement unrestricted
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
  sql_administrator_login_password     = "H@Sh1CoR3!"

  data_exfiltration_protection_enabled = true   # restricts outbound data movement to allow-listed tenants
}
```

## Remediation steps
1. Set `data_exfiltration_protection_enabled = true` (Terraform) or `properties.dataExfiltrationProtectionEnabled: true` (ARM/Bicep) on the workspace.
2. Because this restricts outbound connectivity, you must also configure managed workspace VNET and the allow-listed outbound destinations for any legitimate external data sources/sinks the workspace needs to reach — otherwise valid pipelines may break.
3. This setting typically requires the workspace to use managed virtual network; check that `managed_virtual_network_enabled = true` is also set, since data exfiltration protection depends on it.
4. Test existing pipelines after enabling to confirm no legitimate external connections are unexpectedly blocked, and add them to the allow-list as needed.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SynapseWorkspaceEnablesDataExfilProtection.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SynapseWorkspaceEnablesDataExfilProtection.py)
- [Azure Synapse data exfiltration protection documentation](https://learn.microsoft.com/en-us/azure/synapse-analytics/security/workspace-data-exfiltration-protection)
