# CKV2_AZURE_53: Ensure Azure Synapse Workspace has extended audit logs

## Severity
**LOW** (score: 2.0/10)

Missing extended audit logging on a Synapse workspace reduces forensic visibility into data-plane activity but does not by itself expose data or credentials, so the risk is one of detection gap rather than direct compromise.

## Summary
This check verifies that every Azure Synapse Analytics workspace has an associated extended auditing policy that is enabled, so that database activity in the workspace is recorded.

## Applicability
**Checkov framework(s):** `arm`, `terraform`

- **Terraform**: `azurerm_synapse_workspace` (must be connected to an `azurerm_synapse_workspace_extended_auditing_policy` resource)
- **ARM templates**: `Microsoft.Synapse/workspaces` (must have a nested/associated `Microsoft.Synapse/workspaces/extendedAuditingPolicies` resource)

This is a graph-based connection check, meaning Checkov looks at the relationship between two resources in the IaC configuration rather than a single resource's attributes in isolation.

## Why it matters
Synapse workspaces centralize access to sensitive data across SQL pools, Spark pools, and pipelines. Without extended auditing, there is no durable record of who ran which queries, when data was accessed, or whether a login attempt was anomalous. In the event of a data breach, unauthorized access, or insider misuse, the security team has no forensic trail to reconstruct what happened. Extended auditing writes these events to a storage account, Log Analytics workspace, or Event Hub, which is essential for incident response, regulatory compliance (e.g., PCI-DSS, HIPAA, SOC 2 audit trail requirements), and anomaly detection.

## How Checkov evaluates this
The check is implemented as a JSON graph query (not Python) in both the ARM and Terraform providers.

**Terraform logic:**
- FAIL: an `azurerm_synapse_workspace` resource exists with no connected `azurerm_synapse_workspace_extended_auditing_policy` resource at all.
- PASS: the workspace has a connected `azurerm_synapse_workspace_extended_auditing_policy` resource (the mere existence of the connection is sufficient — the policy resource's `storage_endpoint`/`storage_account_access_key` fields are not further inspected by this check).

**ARM logic:**
- Requires a `Microsoft.Synapse/workspaces/extendedAuditingPolicies` sub-resource connected to the workspace.
- If that sub-resource exists, it additionally requires `properties.state` to either not be present at all, or if present, to equal `"Enabled"`. If `properties.state` is explicitly set to something other than `"Enabled"` (e.g. `"Disabled"`), the check fails.

## Non-compliant example
```hcl
resource "azurerm_synapse_workspace" "example" {
  name                                 = "example-synapse"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = var.sql_admin_password

  identity {
    type = "SystemAssigned"
  }
}
# No azurerm_synapse_workspace_extended_auditing_policy resource defined -> FAILS
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

  identity {
    type = "SystemAssigned"
  }
}

# Added: extended auditing policy connected to the workspace
resource "azurerm_synapse_workspace_extended_auditing_policy" "example" {
  synapse_workspace_id     = azurerm_synapse_workspace.example.id
  storage_endpoint         = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  storage_account_access_key_is_secondary = false
  retention_in_days        = 90
}
```

## Remediation steps
1. Add an `azurerm_synapse_workspace_extended_auditing_policy` resource (Terraform) or an `extendedAuditingPolicies` child resource (ARM) for every Synapse workspace.
2. Reference the workspace's ID/name so Checkov's graph engine can resolve the connection.
3. Point the policy at a storage account, Log Analytics workspace, or Event Hub with an appropriate retention period (align with your org's log retention policy, e.g. 90+ days).
4. For ARM templates, ensure `properties.state` is explicitly set to `"Enabled"` if you set it at all — an explicit `"Disabled"` value will fail the check even if the resource exists.
5. Verify the storage account or Log Analytics destination itself has restricted access, since it will now hold sensitive query/access logs.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/graph_checks/SynapseWorkspaceHasExtendedAuditLogs.json)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/SynapseWorkspaceHasExtendedAuditLogs.json)
