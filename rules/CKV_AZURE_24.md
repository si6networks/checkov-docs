# CKV_AZURE_24: Ensure that 'Auditing' Retention is 'greater than 90 days' for SQL servers

## Severity
**HIGH** (score: 7.5/10)

A short SQL Server audit log retention window (under 90 days) can cause loss of evidence needed to detect and investigate a breach before it is discovered, undermining incident response on a sensitive data store.

## Summary
This check ensures that Azure SQL Server auditing, once enabled, retains logs for at least 90 days rather than the default/short retention window.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: graph-based check over `azurerm_sql_server` / `azurerm_mssql_server`, examining either an inline `extended_auditing_policy.retention_in_days`, or a connected `azurerm_mssql_server_extended_auditing_policy` resource's `retention_in_days`.
- **ARM**: `Microsoft.Sql/servers` resources, examining a nested `auditingSettings`/`auditingPolicies` child resource's `properties.retentionDays` and `properties.state`.
- **Bicep**: graph-based check requiring a connected `Microsoft.Sql/servers/auditingSettings` resource with `properties.retentionDays >= 90` and `properties.state == "Enabled"`.

## Why it matters
SQL Server audit logs are the record used to investigate a suspected breach, insider misuse, or data exfiltration incident after the fact. Security incidents are frequently not detected until weeks or months after the initial compromise — if audit retention is shorter than the actual detection latency, the logs covering the critical initial-access and lateral-movement period will already have been purged by the time an investigation starts, permanently destroying forensic evidence. A 90-day minimum retention window is a common baseline aligned with compliance frameworks (e.g., PCI-DSS requires at least one year with 90 days immediately available; many internal security policies use 90 days as the working minimum) that gives incident responders a realistic chance of reconstructing what happened. This check builds on CKV_AZURE_23 (auditing enabled) by additionally verifying the retention window is long enough to be useful.

## How Checkov evaluates this
- **ARM** (`SQLServerAuditingRetention90Days.py`): walks the resource's nested `resources`, looking for one of type `Microsoft.Sql/servers/databases/auditingSettings`, `Microsoft.Sql/servers/auditingSettings`, `auditingSettings`, or a `databases` sub-resource containing a nested `Microsoft.Sql/servers/databases/auditingPolicies` resource. For whichever audit resource is found, it PASSES only if `properties.state` (case-insensitive) equals `"enabled"` **and** `properties.retentionDays` is >= 90 (accepting either an int or a numeric string). Any other combination, or no matching audit resource at all, FAILS.
- **Bicep** (graph check): requires a `Microsoft.Sql/servers` resource connected to a `Microsoft.Sql/servers/auditingSettings` resource where `properties.retentionDays` exists and is `>= 90`, and `properties.state == "Enabled"`.
- **Terraform** (graph check): requires either (a) `extended_auditing_policy.*.retention_in_days >= 90` inline on the server resource, or (b) for `azurerm_mssql_server` specifically, a connected `azurerm_mssql_server_extended_auditing_policy` resource with `retention_in_days >= 90`.

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.admin_password
}

resource "azurerm_mssql_server_extended_auditing_policy" "example" {
  server_id                              = azurerm_mssql_server.example.id
  storage_endpoint                       = azurerm_storage_account.audit.primary_blob_endpoint
  storage_account_access_key             = azurerm_storage_account.audit.primary_access_key
  storage_account_access_key_is_secondary = false
  retention_in_days                      = 7   # too short -> FAILS
}
```

## Remediated example
```hcl
resource "azurerm_mssql_server_extended_auditing_policy" "example" {
  server_id                              = azurerm_mssql_server.example.id
  storage_endpoint                       = azurerm_storage_account.audit.primary_blob_endpoint
  storage_account_access_key             = azurerm_storage_account.audit.primary_access_key
  storage_account_access_key_is_secondary = false
  retention_in_days                      = 90   # >= 90 days -> PASSES
}
```

## Remediation steps
1. Set `retention_in_days` to `90` or higher on the `azurerm_mssql_server_extended_auditing_policy` (or the equivalent inline `extended_auditing_policy` block on `azurerm_sql_server`/`azurerm_mssql_server`).
2. For ARM/Bicep templates, set `properties.retentionDays >= 90` (and confirm `properties.state = "Enabled"`) on the `auditingSettings` child resource.
3. Confirm this check's companion, CKV_AZURE_23 (auditing enabled at all), also passes — retention is meaningless if auditing itself isn't turned on.
4. Verify the storage account or Log Analytics workspace backing the audit logs has sufficient capacity/lifecycle policy to actually retain 90+ days of data without being purged by an unrelated storage lifecycle rule.
5. If regulatory requirements in your industry mandate longer retention (e.g., 1 year, 7 years), set a value well above the 90-day minimum enforced by this check.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SQLServerAuditingRetention90Days.py
- Checkov check source (Bicep): https://github.com/bridgecrewio/checkov/blob/main/checkov/bicep/checks/graph_checks/SQLServerAuditingRetention90Days.json
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/SQLServerAuditingRetention90Days.json
- Azure docs: https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview
