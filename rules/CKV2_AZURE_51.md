# CKV2_AZURE_51: Ensure Synapse SQL Pool has a security alert policy

## Severity
**LOW** (score: 2.0/10)

Missing a security alert policy on a Synapse SQL Pool is a detective/monitoring gap that delays detection of anomalous or malicious database activity rather than directly enabling an attack.

## Summary
This check ensures every Azure Synapse dedicated SQL Pool has an associated, enabled security alert policy that monitors for anomalous database activities such as SQL injection attempts and unusual access patterns.

## Applicability
- **IaC frameworks:** Terraform (graph-based check), ARM/Bicep (graph-based check)
- **Resource types:** `Microsoft.Synapse/workspaces/sqlPools` connected to `Microsoft.Sql/servers/securityAlertPolicies` (ARM); `azurerm_synapse_sql_pool` connected to `azurerm_synapse_sql_pool_security_alert_policy` (Terraform)

## Why it matters
Synapse SQL Pools host large-scale analytical data warehouses, frequently containing consolidated, cross-department sensitive data (financial records, customer PII, aggregated business intelligence). Advanced Threat Protection / security alert policies detect anomalies like potential SQL injection, unusual data exfiltration volumes, brute-force login attempts, and access from unfamiliar locations — all attack patterns that are otherwise invisible without dedicated monitoring, since normal database logging doesn't distinguish malicious query patterns from legitimate ones. Without an enabled alert policy, an attacker who gains any level of access (compromised credentials, an exploited application-layer SQL injection) can operate for an extended period undetected, especially significant given the volume and sensitivity of data typically warehoused in Synapse.

## How Checkov evaluates this
Graph-based JSON policy (same logic for both ARM and Terraform variants). PASSES only when:
1. The SQL pool (`Microsoft.Synapse/workspaces/sqlPools` / `azurerm_synapse_sql_pool`) is connected to a security alert policy resource.
2. That policy's state attribute (`properties.state` in ARM, `policy_state` in Terraform) equals `"Enabled"` — in the ARM variant, this condition is also satisfied if the `properties.state` attribute simply doesn't exist at all (treated as compliant by the check logic, though this diverges from what "no alert policy" should mean — always confirm actual Azure defaults independently).

FAILS if no security alert policy is connected to the SQL pool, or if the connected policy's state is explicitly something other than `"Enabled"` (e.g., `"Disabled"`).

## Non-compliant example
```hcl
resource "azurerm_synapse_sql_pool" "example" {
  name                 = "examplesqlpool"
  synapse_workspace_id = azurerm_synapse_workspace.example.id
  sku_name             = "DW100c"
  create_mode          = "Default"
  # no azurerm_synapse_sql_pool_security_alert_policy associated
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

resource "azurerm_synapse_sql_pool_security_alert_policy" "example" {
  synapse_workspace_id = azurerm_synapse_workspace.example.id
  sql_pool_id          = azurerm_synapse_sql_pool.example.id
  policy_state         = "Enabled"

  storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
}
```

## Remediation steps
1. Create an `azurerm_synapse_sql_pool_security_alert_policy` resource (or ARM `Microsoft.Sql/servers/securityAlertPolicies`) for every Synapse SQL pool.
2. Set `policy_state = "Enabled"` explicitly.
3. Configure `storage_endpoint`/`storage_account_access_key` (or `disabled_alerts`, `email_addresses` as needed) so alert data is stored and, ideally, forwarded to a monitored destination.
4. Pair this with vulnerability assessment (see CKV2_AZURE_52) for complete coverage — alert policies detect active threats while vulnerability assessment finds latent misconfigurations.
5. Route alerts into Microsoft Defender for Cloud / a SIEM for centralized triage rather than relying solely on individual pool-level notifications.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/SynapseSQLPoolHasSecurityAlertPolicy.json)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/graph_checks/SynapseSQLPoolHasSecurityAlertPolicy.json)
- [Azure Synapse: Advanced Threat Protection documentation](https://learn.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-sql-server-microsoft-defender)
