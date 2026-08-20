# CKV2_AZURE_3: Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server
## Severity
**LOW** (score: 2.0/10)

Without periodic recurring vulnerability scans, newly introduced SQL Server misconfigurations or exposures can go undetected for longer, delaying remediation of otherwise separate security issues.

## Summary
This check verifies that an Azure SQL server has Vulnerability Assessment configured with recurring scans enabled, wired through an active security alert policy.

## Applicability
- **IaC framework:** Terraform (graph-based check)
- **Resource types involved:** `azurerm_sql_server` / `azurerm_mssql_server`, `azurerm_mssql_server_security_alert_policy`, `azurerm_mssql_server_vulnerability_assessment`

## Why it matters
SQL Vulnerability Assessment scans a database for misconfigurations, excessive permissions, unprotected sensitive data, and known security issues. A one-time scan only captures a snapshot; databases drift over time as schemas change, new columns are added, permissions are granted, and configuration changes are made. Without periodic recurring scans, newly introduced vulnerabilities (e.g., a new table storing sensitive data without classification/encryption, an overly broad permission grant, a weak configuration change) can go undetected indefinitely. Recurring scans, combined with an active security alert policy, ensure ongoing drift is caught and reported (typically emailed to security/DBA teams) rather than relying on someone remembering to manually re-run an assessment.

## How Checkov evaluates this
This is a **graph-based** check chaining several conditions:
1. Either an `azurerm_sql_server` or `azurerm_mssql_server` must have a graph connection to an `azurerm_mssql_server_security_alert_policy` resource.
2. That security alert policy's `state` attribute must equal `"Enabled"`.
3. The security alert policy resource must have a graph connection to an `azurerm_mssql_server_vulnerability_assessment` resource.
4. That vulnerability assessment resource's `recurring_scans.*.enabled` attribute must equal `true` (the `.*.` indicates it checks within the `recurring_scans` block for an `enabled` value).
5. The final filter scopes the PASS/FAIL result to the `azurerm_mssql_server_vulnerability_assessment` resource.

If the security alert policy is missing/disabled, or the vulnerability assessment resource is missing, or `recurring_scans.enabled` is not `true`, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = "example-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}

# No security alert policy or vulnerability assessment configured at all.
```

## Remediated example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = "example-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}

resource "azurerm_storage_account" "va" {
  name                     = "examplevastorage"
  resource_group_name      = "example-rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Added: security alert policy in the Enabled state.
resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name        = "example-rg"
  server_name                = azurerm_mssql_server.example.name
  state                      = "Enabled"
  storage_endpoint            = azurerm_storage_account.va.primary_blob_endpoint
  storage_account_access_key  = azurerm_storage_account.va.primary_access_key
}

# Added: vulnerability assessment with recurring scans enabled.
resource "azurerm_mssql_server_vulnerability_assessment" "example" {
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.example.id
  storage_container_path          = "${azurerm_storage_account.va.primary_blob_endpoint}vulnerability-assessment/"
  storage_account_access_key      = azurerm_storage_account.va.primary_access_key

  recurring_scans {
    enabled                   = true
    email_subscription_admins = true
  }
}
```

## Remediation steps
1. Create an `azurerm_mssql_server_security_alert_policy` for the SQL server with `state = "Enabled"`.
2. Create an `azurerm_mssql_server_vulnerability_assessment` referencing that alert policy's ID, pointing to a storage account/container for scan result storage.
3. Set `recurring_scans { enabled = true }` and configure `email_subscription_admins` (or specific `emails`) so findings reach the responsible team.
4. Ensure the storage account used for scan results has appropriate access restrictions (not publicly accessible) since it holds security scan output.
5. Periodically review the delivered scan reports and remediate flagged findings — enabling the scan alone does not fix underlying issues, it only surfaces them.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/VAsetPeriodicScansOnSQL.json)
- [SQL Vulnerability Assessment](https://learn.microsoft.com/en-us/azure/azure-sql/database/sql-vulnerability-assessment)
