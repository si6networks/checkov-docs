# CKV2_AZURE_46: Ensure that Azure Synapse Workspace vulnerability assessment is enabled

## Severity
**MEDIUM** (score: 5.0/10)

Missing vulnerability assessment on a Synapse workspace is a detective/monitoring gap that delays discovery of underlying misconfigurations rather than directly enabling an attack.

## Summary
This check ensures that an Azure Synapse Analytics workspace has vulnerability assessment enabled and configured with recurring scans, so security weaknesses in the underlying SQL pools/workspace are continuously detected.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **IaC frameworks:** Terraform (graph-based check), ARM/Bicep (Python resource-value check)
- **Resource types:** `Microsoft.Synapse/workspaces/vulnerabilityAssessments` (ARM/Bicep), `azurerm_synapse_workspace_security_alert_policy` + `azurerm_synapse_workspace_vulnerability_assessment` (Terraform)

## Why it matters
Azure Synapse workspaces aggregate large-scale data processing and often hold sensitive analytical datasets. Without vulnerability assessment enabled, misconfigurations such as excessive permissions, missing encryption, or exposed sensitive columns can go undetected for the lifetime of the workspace. Given Synapse's broad blast radius (it typically integrates with data lakes, pipelines, and multiple SQL pools), an unassessed security posture increases the risk that a single overlooked weakness — e.g., an overly permissive role assignment — is exploited to exfiltrate large volumes of data. Continuous vulnerability scanning provides an automated, recurring check against a known baseline of SQL/data-platform security best practices, catching drift introduced by ad-hoc changes.

## How Checkov evaluates this
**ARM (Python check, `SynapseWorkspaceVAisEnabled`, a `BaseResourceValueCheck`):** Inspects the `Microsoft.Synapse/workspaces/vulnerabilityAssessments` resource's `properties/recurringScans/isEnabled` key. PASSES only if this key is present and set to `true`; FAILS otherwise (including if the key is missing).

**Terraform (graph-based JSON policy):** PASSES only when all of the following hold:
1. `azurerm_synapse_workspace_security_alert_policy` is connected to an `azurerm_synapse_workspace`.
2. `azurerm_synapse_workspace_vulnerability_assessment` is connected to that security alert policy.
3. On the vulnerability assessment resource, `recurring_scans.*.enabled` equals `true`.

If the vulnerability assessment resource is missing, not connected to the security alert policy, or `recurring_scans.enabled` is not `true`, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_synapse_workspace" "example" {
  name                                 = "examplesynapseworkspace"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = var.synapse_password
}

resource "azurerm_synapse_workspace_security_alert_policy" "example" {
  workspace_id = azurerm_synapse_workspace.example.id
  state        = "Enabled"
}

# no azurerm_synapse_workspace_vulnerability_assessment resource defined
```

## Remediated example
```hcl
resource "azurerm_synapse_workspace_security_alert_policy" "example" {
  workspace_id = azurerm_synapse_workspace.example.id
  state        = "Enabled"
}

resource "azurerm_synapse_workspace_vulnerability_assessment" "example" {
  workspace_security_alert_policy_id = azurerm_synapse_workspace_security_alert_policy.example.id
  storage_container_path             = "${azurerm_storage_account.example.primary_blob_endpoint}${azurerm_storage_container.example.name}/"

  recurring_scans {
    enabled                   = true      # enables scheduled vulnerability scans
    email_subscription_admins = true
  }
}
```

## Remediation steps
1. Create an `azurerm_synapse_workspace_security_alert_policy` (or ARM `Microsoft.Sql/servers/securityAlertPolicies`-equivalent) resource with `state = "Enabled"`.
2. Attach an `azurerm_synapse_workspace_vulnerability_assessment` resource, or set `properties.recurringScans.isEnabled = true` in ARM/Bicep, to that policy.
3. Set `recurring_scans.enabled = true` and configure email notification (`email_subscription_admins` and/or `emails`) so findings reach a monitored inbox.
4. Ensure the storage account used for scan report storage has restrictive access controls, since reports may reveal exploitable weaknesses.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureSynapseWorkspaceVAisEnabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureSynapseWorkspaceVAisEnabled.json)
- [Azure Synapse vulnerability assessment documentation](https://learn.microsoft.com/en-us/azure/synapse-analytics/security/synapse-vulnerability-assessment)
