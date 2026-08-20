# CKV2_AZURE_13: Ensure that sql servers enables data security policy

## Severity
**LOW** (score: 2.0/10)

Disabling the SQL server security alert policy removes detection of anomalous activity such as SQL injection and brute-force attempts, delaying response to an active compromise of a sensitive data store.

## Summary
This check ensures an Azure SQL Server (`azurerm_sql_server`) has a Security Alert Policy (Advanced Threat Protection) attached and that its `state` is set to `Enabled`.

## Applicability
- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `azurerm_sql_server`, connected via `azurerm_mssql_server_security_alert_policy`.

## Why it matters
SQL Server's Advanced Threat Protection / Security Alert Policy detects anomalous database activity such as SQL injection attempts, brute-force login attacks, unusual data access patterns, and access from unfamiliar locations — surfacing these as security alerts (optionally emailed to admins/security teams). Without this policy enabled, an active attack against the database — including successful SQL injection exfiltrating data, or a compromised credential being used to dump tables — can go completely undetected until the damage is discovered through other means (e.g. a customer complaint, a ransom note, or an audit). Enabling threat detection is a low-cost, high-value detective control especially important for SQL Servers exposed to application tiers that process untrusted user input.

## How Checkov evaluates this
Graph check (`AzureMSSQLServerHasSecurityAlertPolicy.json`). Logic, filtered to `azurerm_sql_server` resources, flags **failure** if either:
1. The SQL server has **no** connected `azurerm_mssql_server_security_alert_policy` resource at all, **or**
2. It has a connected security alert policy, but that policy's `state` attribute is **not** equal to `"Enabled"`.

PASS requires a connected security alert policy with `state = "Enabled"`.

## Non-compliant example
```hcl
resource "azurerm_sql_server" "sql" {
  name                         = "app-sql-server"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = azurerm_resource_group.rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}
# No azurerm_mssql_server_security_alert_policy -> fails
```

## Remediated example
```hcl
resource "azurerm_sql_server" "sql" {
  name                         = "app-sql-server"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = azurerm_resource_group.rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}

resource "azurerm_mssql_server_security_alert_policy" "alert_policy" {
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_sql_server.sql.name
  state               = "Enabled"

  email_account_admins = true
  storage_endpoint     = azurerm_storage_account.audit.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.audit.primary_access_key
}
```

## Remediation steps
1. Add an `azurerm_mssql_server_security_alert_policy` resource referencing the SQL server's `resource_group_name` and `server_name`.
2. Set `state = "Enabled"`.
3. Set `email_account_admins = true` (or configure `email_addresses`) so alerts reach the security/ops team promptly.
4. Optionally configure `storage_endpoint`/`storage_account_access_key` to persist detailed threat-detection logs to a storage account for retention and forensic review.
5. This is additive; no downtime to the SQL server is required.
6. Consider pairing this with Microsoft Defender for SQL (formerly Advanced Data Security) at the subscription level for broader vulnerability assessment coverage alongside threat detection.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureMSSQLServerHasSecurityAlertPolicy.json)
- [Azure: Microsoft Defender for SQL / Advanced Threat Protection](https://learn.microsoft.com/en-us/azure/azure-sql/database/threat-detection-overview)
