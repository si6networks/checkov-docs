# CKV2_AZURE_54: Ensure log monitoring is enabled for Synapse SQL Pool

## Severity
**LOW** (score: 2.0/10)

Lack of auditing on a Synapse SQL Pool limits the ability to detect and investigate unauthorized queries or data exfiltration against a data warehouse, which is a monitoring gap rather than an open access path.

## Summary
This check verifies that every Synapse dedicated SQL pool has an associated auditing/extended-auditing policy with log monitoring enabled, so that queries run against the SQL pool are recorded.

## Applicability
**Checkov framework(s):** `arm`, `terraform`

- **Terraform**: `azurerm_synapse_sql_pool` (must be connected to an `azurerm_synapse_sql_pool_extended_auditing_policy` resource)
- **ARM templates**: `Microsoft.Synapse/workspaces/sqlPools` (must have a nested `Microsoft.Synapse/workspaces/sqlPools/auditingSettings` resource)

This is a graph-based connection check evaluating the relationship between the SQL pool resource and its auditing policy resource.

## Why it matters
Dedicated SQL pools store and serve large-scale relational/analytical data, frequently containing sensitive business or customer data. Without log monitoring, DBAs and security teams cannot see who queried what data, detect exfiltration attempts, or investigate anomalous access patterns after the fact. This gap undermines both breach investigation and routine compliance reporting (e.g., demonstrating least-privilege access was actually followed), and it is a common audit finding in regulated environments (finance, healthcare).

## How Checkov evaluates this
Implemented as a JSON graph query in both providers.

**Terraform logic:**
- FAIL: `azurerm_synapse_sql_pool` has no connected `azurerm_synapse_sql_pool_extended_auditing_policy` resource.
- FAIL: the policy exists but sets `log_monitoring_enabled = false`.
- PASS: the policy exists and either omits `log_monitoring_enabled` (defaults to enabled) or explicitly sets it to `true`.

**ARM logic:**
- Requires `Microsoft.Synapse/workspaces/sqlPools/auditingSettings` to be connected to the SQL pool.
- If present, `properties.state` must either be absent or equal `"Enabled"`; an explicit non-`"Enabled"` value fails.

## Non-compliant example
```hcl
resource "azurerm_synapse_sql_pool" "example" {
  name                 = "examplesqlpool"
  synapse_workspace_id = azurerm_synapse_workspace.example.id
  sku_name             = "DW100c"
  create_mode          = "Default"
}

resource "azurerm_synapse_sql_pool_extended_auditing_policy" "example" {
  synapse_sql_pool_id       = azurerm_synapse_sql_pool.example.id
  storage_endpoint          = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  log_monitoring_enabled    = false   # explicitly disabled -> FAILS
}
```

## Remediated example
```hcl
resource "azurerm_synapse_sql_pool" "example" {
  name                 = "examplesqlpool"
  synapse_workspace_id = azurerm_synapse_workspace.example.id
  sku_name             = "DW100c"
  create_mode          = "Default"
}

resource "azurerm_synapse_sql_pool_extended_auditing_policy" "example" {
  synapse_sql_pool_id       = azurerm_synapse_sql_pool.example.id
  storage_endpoint          = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  log_monitoring_enabled    = true   # fixed: log monitoring enabled
}
```

## Remediation steps
1. Create an `azurerm_synapse_sql_pool_extended_auditing_policy` resource for every `azurerm_synapse_sql_pool`.
2. Do not set `log_monitoring_enabled = false`; either omit the attribute or set it to `true`.
3. Point `storage_endpoint`/`storage_account_access_key` (or a Log Analytics workspace ID, depending on provider version) at a secured logging destination with adequate retention.
4. For ARM templates, ensure the `auditingSettings` sub-resource's `properties.state` is `"Enabled"` if specified.
5. Confirm the storage/monitoring destination is itself access-restricted, since audit logs may contain sensitive query text or parameter values.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/graph_checks/SynapseLogMonitoringEnabledForSQLPool.json)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/SynapseLogMonitoringEnabledForSQLPool.json)
