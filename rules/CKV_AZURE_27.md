# CKV_AZURE_27: Ensure that 'Email service and co-administrators' is 'Enabled' for MSSQL servers

## Severity
**LOW** (score: 2.0/10)

Not routing threat-detection alerts to the service's co-administrators/owners is an alerting-distribution gap that slows incident response but does not itself weaken the server's security posture.

## Summary
This check ensures an Azure SQL Server's threat-detection security alert policy is configured to also email the subscription's service administrators and co-administrators, not just a custom recipient list.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, ARM, Bicep (via shared entities)
- **Resource types:** `Microsoft.Sql/servers/databases` (nested `securityAlertPolicies`), `azurerm_mssql_server_security_alert_policy`

## Why it matters
Custom email recipient lists (see CKV_AZURE_26) can go stale — distribution lists get decommissioned, individual mailboxes get abandoned, or the list is simply never updated as teams reorganize. Enabling notifications to the subscription's service administrators and co-administrators provides a fallback channel that is tied to the Azure subscription's actual ownership/RBAC structure rather than a hand-maintained list, ensuring that whoever currently has administrative authority over the subscription is notified of detected SQL threats even if the custom alert list is broken or forgotten.

## How Checkov evaluates this
**ARM check**: iterates nested `resources` for a `securityAlertPolicies` type. **PASS** only if `properties.state` is `"enabled"` (case-insensitive) AND `properties.emailAccountAdmins` is truthy. Otherwise **FAIL**.

**Terraform check** (`BaseResourceValueCheck`): inspects `azurerm_mssql_server_security_alert_policy.email_account_admins`. **PASS** if it is set to the expected truthy value; **FAIL** if missing/false.

## Non-compliant example
```hcl
resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mssql_server.example.name
  state               = "Enabled"
  email_addresses     = ["secops@example.com"]
  # email_account_admins not set (defaults to false)
}
```

## Remediated example
```hcl
resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mssql_server.example.name
  state               = "Enabled"
  email_addresses     = ["secops@example.com"]
  email_account_admins = true   # added
}
```

## Remediation steps
1. Set `email_account_admins = true` on the `azurerm_mssql_server_security_alert_policy` resource.
2. For ARM/Bicep templates, set `properties.emailAccountAdmins` to `true` on the `securityAlertPolicies` sub-resource.
3. Verify that the subscription's service administrator and co-administrator roles are actually assigned to people who monitor their inbox — this setting is only as useful as the freshness of those role assignments.
4. Use together with CKV_AZURE_25 (all threat types enabled) and CKV_AZURE_26 (custom email list) for complete alerting coverage.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerEmailAlertsToAdminsEnabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SQLServerEmailAlertsToAdminsEnabled.py)
- [Azure SQL threat detection](https://learn.microsoft.com/en-us/azure/azure-sql/database/threat-detection-overview)
