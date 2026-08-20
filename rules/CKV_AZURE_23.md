# CKV_AZURE_23: Ensure that 'Auditing' is set to 'Enabled' for SQL servers

## Severity
**LOW** (score: 2.0/10)

Disabling SQL Server auditing removes the audit trail needed to detect and investigate unauthorized data access or tampering on a sensitive data store.

## Summary
This check ensures that auditing is enabled for Azure SQL servers (and/or their databases), so that database events (logins, query execution, schema/data changes) are recorded for security monitoring and forensics.

## Applicability
- **Terraform**: graph-based check across `azurerm_sql_server` / `azurerm_mssql_server`, in combination with either an inline `extended_auditing_policy` block or a separate connected `azurerm_mssql_server_extended_auditing_policy` resource.
- **ARM**: `Microsoft.Sql/servers` and `Microsoft.Sql/servers/databases`, checking for a nested/associated `auditingSettings` sub-resource.
- **Bicep**: graph-based check over the same `Microsoft.Sql/servers` / `Microsoft.Sql/servers/databases` resource types, following the connection to `Microsoft.Sql/servers/auditingSettings` or `Microsoft.Sql/servers/databases/auditingSettings`.

## Why it matters
SQL Server auditing captures database events to an audit log store (storage account, Log Analytics workspace, or Event Hub). Without it, there is no record of who accessed the database, what queries ran, or what data was changed — which severely limits incident response and forensic investigation after a suspected breach, insider misuse, or data exfiltration event. Many compliance frameworks (PCI-DSS, HIPAA, SOC 2, ISO 27001) explicitly require database-level audit trails for systems handling sensitive or regulated data. Auditing is also frequently the only way to detect anomalous query patterns (e.g., a compromised credential running mass SELECT * exports) after the fact.

## How Checkov evaluates this
- **ARM** (`SQLServerAuditingEnabled.py`): iterates the resource's nested `resources` list looking for one whose `type` is `auditingSettings`, `Microsoft.Sql/servers/auditingSettings`, or `Microsoft.Sql/servers/databases/auditingSettings`. If found, it reads `properties.state` and PASSES only if that value, lower-cased, equals `"enabled"`. If no such resource exists, or `state` isn't `"enabled"`, the check FAILS.
- **Bicep** (graph check `SQLServerAuditingEnabled.json`): filters for `Microsoft.Sql/servers` or `Microsoft.Sql/servers/databases`, then requires a connected `.../auditingSettings` resource whose `properties.state` attribute equals `"Enabled"`.
- **Terraform** (graph check `SQLServerAuditingEnabled.json`): filters for `azurerm_sql_server` or `azurerm_mssql_server`. It PASSES if either (a) the server resource itself has an `extended_auditing_policy` block present, OR (b) for `azurerm_mssql_server` specifically, there's a connected `azurerm_mssql_server_extended_auditing_policy` resource whose `server_id` references it.

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.admin_password
  # No extended_auditing_policy block and no separate policy resource -> FAILS
}
```

## Remediated example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.admin_password
}

resource "azurerm_storage_account" "audit" {
  name                     = "sqlauditlogs"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Adds the audit policy connection -> PASSES
resource "azurerm_mssql_server_extended_auditing_policy" "example" {
  server_id                              = azurerm_mssql_server.example.id
  storage_endpoint                       = azurerm_storage_account.audit.primary_blob_endpoint
  storage_account_access_key             = azurerm_storage_account.audit.primary_access_key
  storage_account_access_key_is_secondary = false
  retention_in_days                      = 90
}
```

## Remediation steps
1. Add an `extended_auditing_policy` block directly on `azurerm_mssql_server`/`azurerm_sql_server`, or create a separate `azurerm_mssql_server_extended_auditing_policy` resource referencing the server via `server_id`.
2. Point the audit destination at a durable store: a storage account (`storage_endpoint` + access key), a Log Analytics workspace, or an Event Hub, depending on your SIEM integration.
3. Pair this with CKV_AZURE_24 (retention >= 90 days) to ensure logs are kept long enough for investigations.
4. For ARM/Bicep templates, ensure the `Microsoft.Sql/servers/auditingSettings` (or database-level `auditingSettings`) child resource is deployed alongside the server, with `properties.state` set to `"Enabled"`.
5. Route audit logs to a workspace with restricted write access and retention/immutability controls so the audit trail itself cannot be tampered with by a compromised account.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SQLServerAuditingEnabled.py
- Checkov check source (Bicep): https://github.com/bridgecrewio/checkov/blob/main/checkov/bicep/checks/graph_checks/SQLServerAuditingEnabled.json
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/SQLServerAuditingEnabled.json
- Azure docs: https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview
