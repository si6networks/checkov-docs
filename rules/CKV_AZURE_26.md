# CKV_AZURE_26: Ensure that 'Send Alerts To' is enabled for MSSQL servers

## Severity
**HIGH** (score: 7.5/10)

Missing 'Send Alerts To' configuration only delays awareness of SQL security events already captured by threat detection, a minor operational-visibility gap rather than a direct exploitable weakness.

## Summary
This check ensures that an Azure SQL Server's threat-detection security alert policy has at least one recipient email address configured, so detected threats are actually delivered to someone.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, ARM, Bicep (via shared entities)
- **Resource types:** `Microsoft.Sql/servers/databases` (nested `securityAlertPolicies`), `azurerm_mssql_server_security_alert_policy`

## Why it matters
Enabling SQL threat detection (see CKV_AZURE_25) is only half the story — if no email recipients are configured, detected anomalies (SQL injection attempts, brute force, unusual access patterns) are logged but never actively surfaced to security or on-call staff. In practice, alerts that nobody is notified about are effectively invisible; incident response depends on someone actually seeing the alert in time to act. Requiring at least one address in `email_addresses` / `emailAddresses` closes this gap by making sure detected threats trigger real-time email notification, in addition to whatever is visible in the Azure portal or SIEM pipeline.

## How Checkov evaluates this
**ARM check**: iterates nested `resources` for a `securityAlertPolicies` type. **PASS** only if `properties.state` is `"enabled"` (case-insensitive) AND `properties.emailAddresses` is truthy/non-empty. Otherwise **FAIL**.

**Terraform check** (`BaseResourceValueCheck` with `ANY_VALUE`): inspects `azurerm_mssql_server_security_alert_policy.email_addresses`. **PASS** if the attribute is set to any non-empty value; **FAIL** if it is missing or empty.

## Non-compliant example
```hcl
resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mssql_server.example.name
  state               = "Enabled"
  # email_addresses not set -> no one is notified
}
```

## Remediated example
```hcl
resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mssql_server.example.name
  state               = "Enabled"

  email_addresses = ["secops@example.com"]   # added
}
```

## Remediation steps
1. Set `email_addresses` on the `azurerm_mssql_server_security_alert_policy` resource to at least one valid, monitored distribution list or on-call address.
2. For ARM/Bicep templates, set `properties.emailAddresses` on the `securityAlertPolicies` sub-resource.
3. Prefer a team distribution list over an individual's mailbox to avoid alert loss during staff turnover/leave.
4. Combine with CKV_AZURE_27 (email service and co-administrators) for full alerting coverage.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerEmailAlertsEnabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SQLServerEmailAlertsEnabled.py)
- [Azure SQL threat detection](https://learn.microsoft.com/en-us/azure/azure-sql/database/threat-detection-overview)
