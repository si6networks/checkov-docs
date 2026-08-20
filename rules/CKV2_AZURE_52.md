# CKV2_AZURE_52: Ensure Synapse SQL Pool has vulnerability assessment attached

## Severity
**LOW** (score: 2.0/10)

Missing vulnerability assessment on a Synapse SQL Pool is a detective/monitoring gap that delays discovery of underlying database misconfigurations rather than directly enabling an attack.

## Summary
This check ensures every Azure Synapse dedicated SQL Pool has vulnerability assessment enabled (chained through its security alert policy), so the pool's configuration is regularly scanned for known security weaknesses.

## Applicability
- **IaC frameworks:** Terraform (graph-based check), ARM/Bicep (graph-based check)
- **Resource types:** `Microsoft.Synapse/workspaces/sqlPools` → `Microsoft.Sql/servers/securityAlertPolicies` → `Microsoft.Sql/servers/vulnerabilityAssessments` (ARM); `azurerm_synapse_sql_pool` → `azurerm_synapse_sql_pool_security_alert_policy` → `azurerm_synapse_sql_pool_vulnerability_assessment` (Terraform)

## Why it matters
This check complements CKV2_AZURE_51: while a security alert policy detects active/anomalous behavior, vulnerability assessment proactively scans the SQL pool's configuration for known weaknesses — such as excessive user permissions, missing auditing, unencrypted sensitive columns, and outdated authentication mechanisms — against a Microsoft-maintained rule set. Given that Synapse SQL Pools typically warehouse large volumes of consolidated, high-value data, an unassessed pool can silently accumulate configuration drift (e.g., a broad `db_owner` grant added for a one-off task and never revoked) that a periodic scan would catch and flag for remediation before it's exploited.

## How Checkov evaluates this
Graph-based JSON policy (both ARM and Terraform variants share the logic). PASSES only when all hold:
1. The SQL pool is connected to a security alert policy resource.
2. That security alert policy is connected to a vulnerability assessment resource.
3. On the vulnerability assessment resource, recurring scans are enabled: `properties.recurringScans.isEnabled` equals `true` in ARM (or is simply absent, which the ARM check treats as passing — verify actual Azure defaults independently); `recurring_scans.*.enabled` equals `true` in Terraform (no such absence exception in the Terraform variant).

FAILS when no vulnerability assessment is connected to the chain, or when it exists but recurring scans are explicitly disabled.

## Non-compliant example
```hcl
resource "azurerm_synapse_sql_pool_security_alert_policy" "example" {
  synapse_workspace_id = azurerm_synapse_workspace.example.id
  sql_pool_id          = azurerm_synapse_sql_pool.example.id
  policy_state         = "Enabled"

  storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
}

# no azurerm_synapse_sql_pool_vulnerability_assessment resource defined
```

## Remediated example
```hcl
resource "azurerm_synapse_sql_pool_security_alert_policy" "example" {
  synapse_workspace_id = azurerm_synapse_workspace.example.id
  sql_pool_id          = azurerm_synapse_sql_pool.example.id
  policy_state         = "Enabled"

  storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
}

resource "azurerm_synapse_sql_pool_vulnerability_assessment" "example" {
  security_alert_policy_id = azurerm_synapse_sql_pool_security_alert_policy.example.id
  storage_container_path   = "${azurerm_storage_account.example.primary_blob_endpoint}${azurerm_storage_container.example.name}/"

  recurring_scans {
    enabled                   = true       # enables scheduled vulnerability scans on the pool
    email_subscription_admins = true
  }
}
```

## Remediation steps
1. Ensure the SQL pool has an enabled `azurerm_synapse_sql_pool_security_alert_policy` (see CKV2_AZURE_51), a prerequisite for attaching vulnerability assessment.
2. Add an `azurerm_synapse_sql_pool_vulnerability_assessment` resource referencing that alert policy's ID.
3. Set `recurring_scans.enabled = true` and configure notification recipients (`email_subscription_admins`, `emails`) so findings are actively reviewed.
4. Ensure the storage account holding scan reports is itself secured (private endpoint, restricted RBAC) since reports detail exploitable weaknesses.
5. Periodically review and action findings — enabling the scan alone provides no security benefit without a remediation workflow behind it.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/SynapseSQLPoolHasVulnerabilityAssessment.json)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/graph_checks/SynapseSQLPoolHasVulnerabilityAssessment.json)
- [Azure Synapse: Vulnerability assessment documentation](https://learn.microsoft.com/en-us/azure/synapse-analytics/security/synapse-vulnerability-assessment)
