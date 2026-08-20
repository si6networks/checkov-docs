# CKV2_AZURE_5: Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server

## Severity
**LOW** (score: 2.0/10)

This check ensures vulnerability-assessment alert emails reach admins and subscription owners, a detective/monitoring notification gap rather than a control that directly prevents exploitation.

## Summary
This check ensures an Azure SQL server's vulnerability assessment is configured to notify subscription admins/owners (or an explicit email list) whenever recurring vulnerability scans complete.

## Applicability
- **IaC framework:** Terraform (graph-based check)
- **Resource types:** `azurerm_mssql_server` / `azurerm_sql_server` connected to `azurerm_mssql_server_security_alert_policy`, connected to `azurerm_mssql_server_vulnerability_assessment`

## Why it matters
This check is closely related to CKV2_AZURE_4 and checks essentially the same underlying condition (that scan reports actually reach someone), verifying that the "notify admins and subscription owners" option specifically is functioning as intended. If vulnerability assessment runs but no one is notified of findings, security weaknesses discovered by the scan (weak configurations, missing auditing, excessive permissions) go unnoticed until an incident occurs or a manual audit happens to catch them. Because SQL servers frequently hold an organization's most sensitive structured data, a delay in surfacing and remediating a discovered vulnerability translates directly into a longer window during which an attacker could exploit it. Notification-based alerting closes the loop between automated detection and human remediation action.

## How Checkov evaluates this
Graph-based JSON policy, PASSES only when all hold:
1. The SQL server (`azurerm_sql_server` or `azurerm_mssql_server`) is connected to an `azurerm_mssql_server_security_alert_policy`.
2. That alert policy's `state` equals `"Enabled"`.
3. The alert policy is connected to an `azurerm_mssql_server_vulnerability_assessment`.
4. On the vulnerability assessment, either `recurring_scans.*.email_subscription_admins` equals `true`, **or** `recurring_scans.*.emails` exists (an explicit list is configured).

If the security alert policy is disabled/missing, or the vulnerability assessment has neither admin notification enabled nor an explicit email list, the check FAILS.

## Non-compliant example
```hcl
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
    # emails not set either -> nobody is notified of findings
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
    email_subscription_admins = true                    # notify subscription admins/owners
    emails                    = ["dba-team@example.com"] # and/or a specific distribution list
  }
}
```

## Remediation steps
1. Ensure the SQL server has an `azurerm_mssql_server_security_alert_policy` with `state = "Enabled"`.
2. Attach an `azurerm_mssql_server_vulnerability_assessment` resource to that policy.
3. In its `recurring_scans` block, set `email_subscription_admins = true` (to notify subscription admins/owners) and/or populate `emails` with additional recipients (e.g., a DBA or security team distribution list).
4. Confirm the recipient mailboxes are actively monitored — configuring notification is only useful if findings are triaged and remediated in a timely manner.
5. Consider integrating scan results with a SIEM or ticketing system for tracked remediation rather than relying on email alone.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/VAconfiguredToSendReportsToAdmins.json)
- [Azure SQL Vulnerability Assessment documentation](https://learn.microsoft.com/en-us/azure/azure-sql/database/sql-vulnerability-assessment)
