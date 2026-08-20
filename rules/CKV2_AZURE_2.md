# CKV2_AZURE_2: Ensure that Vulnerability Assessment (VA) is enabled on a SQL server by setting a Storage Account

## Severity
**LOW** (score: 2.0/10)

Without vulnerability assessment scanning, misconfigurations and vulnerabilities in a SQL server's schema and permissions can go undetected, delaying remediation of exploitable weaknesses.

## Summary
This check ensures an Azure SQL Server has a Security Alert Policy attached and enabled, which underpins the Vulnerability Assessment feature that scans databases for misconfigurations and stores results in a linked storage account.

## Applicability
- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `azurerm_sql_server` and `azurerm_mssql_server`, connected via `azurerm_mssql_server_security_alert_policy`.

## Why it matters
SQL Vulnerability Assessment periodically scans databases for security misconfigurations such as excessive permissions, missing auditing, unencrypted sensitive columns, weak authentication settings, and outdated configurations — surfacing them as a prioritized report. This scanning and reporting pipeline depends on the underlying Security Alert Policy being enabled (and typically a storage account configured to persist scan results/baselines). Without an enabled alert policy, an organization loses both real-time threat detection and periodic vulnerability reporting for the SQL server, meaning misconfigurations (like overly permissive `db_owner` role grants, or a table containing SSNs without encryption) can go unnoticed indefinitely, and active exploitation attempts (e.g. SQL injection, credential stuffing) produce no alert to responders.

## How Checkov evaluates this
Graph check (`VAisEnabledInStorageAccount.json`). PASS requires **all** of:
1. Filter to `azurerm_sql_server` or `azurerm_mssql_server` resources.
2. The server must have a **connection** to an `azurerm_mssql_server_security_alert_policy` resource.
3. That security alert policy's `state` attribute must equal `"Enabled"`.

FAIL if the server has no connected security alert policy, or the connected policy's `state` is anything other than `"Enabled"`. (Note: despite the policy title referencing a "Storage Account," the graph definition itself checks the alert policy's connection and `state` — the storage account linkage is typically configured on the same `azurerm_mssql_server_security_alert_policy` resource via its `storage_endpoint`/`storage_account_access_key` attributes, which is where VA scan results get persisted.)

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "sql" {
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
resource "azurerm_mssql_server" "sql" {
  name                         = "app-sql-server"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = azurerm_resource_group.rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}

resource "azurerm_storage_account" "va_results" {
  name                     = "sqlvaresults"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_mssql_server_security_alert_policy" "alert_policy" {
  resource_group_name        = azurerm_resource_group.rg.name
  server_name                = azurerm_mssql_server.sql.name
  state                      = "Enabled"
  storage_endpoint           = azurerm_storage_account.va_results.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.va_results.primary_access_key
  email_account_admins       = true
}

resource "azurerm_mssql_server_vulnerability_assessment" "va" {
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.alert_policy.id
  storage_container_path          = "${azurerm_storage_account.va_results.primary_blob_endpoint}vulnerability-assessment/"
  storage_account_access_key      = azurerm_storage_account.va_results.primary_access_key

  recurring_scans {
    enabled                   = true
    email_subscription_admins = true
  }
}
```

## Remediation steps
1. Add an `azurerm_mssql_server_security_alert_policy` resource for the SQL server with `state = "Enabled"`.
2. Configure `storage_endpoint` and `storage_account_access_key` on that policy pointing to a dedicated storage account for persisting scan/alert data.
3. Add an `azurerm_mssql_server_vulnerability_assessment` resource referencing the security alert policy's ID, and enable `recurring_scans` so VA reports run on an ongoing schedule, not just once.
4. Restrict access to the storage account holding VA results — it will contain details about your database's security posture and should not be broadly readable.
5. This is additive infrastructure; no SQL server downtime or replacement is required.
6. Review VA findings regularly and integrate them into your patch/config-remediation workflow — enabling the feature alone provides no benefit if reports are never actioned.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/VAisEnabledInStorageAccount.json)
- [Azure SQL: Vulnerability Assessment](https://learn.microsoft.com/en-us/azure/azure-sql/database/sql-vulnerability-assessment)
