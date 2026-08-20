# CKV2_AZURE_4: Ensure Azure SQL server ADS VA Send scan reports to is configured

## Severity
**LOW** (score: 2.0/10)

This check ensures vulnerability-assessment scan reports are actually delivered, which is a detective/monitoring control gap rather than a control that directly prevents exploitation.

## Summary
This check ensures that Azure SQL server's Advanced Data Security (ADS) vulnerability assessment is enabled and configured to actually send its recurring scan reports somewhere (either to subscription admins or to a specified email list).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based connection check)
- **Resource types:** `azurerm_mssql_server` / `azurerm_sql_server` connected to `azurerm_mssql_server_security_alert_policy`, which must connect to `azurerm_mssql_server_vulnerability_assessment`

## Why it matters
Azure SQL's vulnerability assessment feature periodically scans the database for misconfigurations and security weaknesses (missing encryption, excessive permissions, outdated auth, etc.), but the scan results are only useful if someone actually sees them. If recurring scans run but no report distribution is configured (no admin email subscription and no explicit email list), vulnerability findings sit unreviewed, meaning newly introduced weaknesses (e.g., a service account with excessive privileges, or a table storing sensitive data without encryption) can persist undetected indefinitely. This directly undermines a compliance control (many frameworks like PCI-DSS and ISO 27001 require documented, actioned vulnerability management) and creates a false sense of security — the tooling is running, but nobody is alerted to act on it.

## How Checkov evaluates this
Graph-based JSON policy. PASSES only when all of these hold:
1. The SQL server (`azurerm_sql_server` or `azurerm_mssql_server`) is connected to an `azurerm_mssql_server_security_alert_policy` resource.
2. That alert policy's `state` attribute equals `"Enabled"`.
3. The alert policy is connected to an `azurerm_mssql_server_vulnerability_assessment` resource.
4. On that vulnerability assessment resource, either `recurring_scans.*.email_subscription_admins` equals `true`, **or** `recurring_scans.emails` exists (an explicit distribution list is configured).

If the security alert policy is missing/disabled, or the vulnerability assessment exists but has neither admin email subscription enabled nor an explicit email list, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_password
}

resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name = azurerm_resource_group.example.name
  server_name          = azurerm_mssql_server.example.name
  state                = "Enabled"
}

resource "azurerm_mssql_server_vulnerability_assessment" "example" {
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.example.id
  storage_container_path          = "${azurerm_storage_account.example.primary_blob_endpoint}${azurerm_storage_container.example.name}/"

  recurring_scans {
    enabled                   = true
    email_subscription_admins = false
    # no emails list set either
  }
}
```

## Remediated example
```hcl
resource "azurerm_mssql_server_vulnerability_assessment" "example" {
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.example.id
  storage_container_path          = "${azurerm_storage_account.example.primary_blob_endpoint}${azurerm_storage_container.example.name}/"

  recurring_scans {
    enabled                   = true
    email_subscription_admins = true                          # send to subscription admins
    emails                    = ["secops@example.com"]         # and/or an explicit distribution list
  }
}
```

## Remediation steps
1. Ensure `azurerm_mssql_server_security_alert_policy` exists for the SQL server with `state = "Enabled"`.
2. Attach an `azurerm_mssql_server_vulnerability_assessment` resource to that alert policy.
3. In the `recurring_scans` block, set `email_subscription_admins = true` and/or populate `emails` with a monitored distribution list (e.g., a security operations mailbox).
4. Ensure the storage account referenced by `storage_container_path` has appropriate access controls, since scan reports may contain sensitive findings.
5. Route the report emails into a triage/ticketing workflow so findings are actually acted upon, not just received.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/VAconfiguredToSendReports.json)
- [Azure SQL Vulnerability Assessment documentation](https://learn.microsoft.com/en-us/azure/azure-sql/database/sql-vulnerability-assessment)
