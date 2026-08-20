# CKV_AZURE_31: Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server

## Severity
**LOW** (score: 2.0/10)

Without connection logging, security-relevant events such as failed authentication attempts and unusual connection sources go unrecorded, hampering detection and forensic investigation of a PostgreSQL server compromise.

## Summary
This check ensures the PostgreSQL server configuration parameter `log_connections` is turned on, so every client connection attempt is recorded in the server logs.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, ARM, Bicep (via shared entities)
- **Resource types:** `Microsoft.DBforPostgreSQL/servers/configurations` (and generic `configurations` with `parent_type = Microsoft.DBforPostgreSQL/servers`), `azurerm_postgresql_configuration`

## Why it matters
`log_connections` records each successful connection attempt to the database, including the connecting host and authenticated role. Without this logging, there is no audit trail of who connected to the database and when — which is essential for detecting unauthorized access attempts, investigating a suspected breach, or reconstructing a timeline during incident response. Many compliance frameworks (PCI-DSS, SOC 2, ISO 27001) explicitly require connection auditing for systems holding regulated data, so disabling this parameter creates both a security-monitoring blind spot and a compliance gap.

## How Checkov evaluates this
**ARM check**: applies to the `configurations` resource named `log_connections` under `Microsoft.DBforPostgreSQL/servers`. **PASS** if `properties.value` (case-insensitive) equals `"on"`; **FAIL** if it's anything else (e.g., `"off"`); **FAIL** if there's no `type` at all in the config.

**Terraform check**: inspects `azurerm_postgresql_configuration`'s `name`/`value`. **FAIL** only if `name == "log_connections"` and `value == "off"`; **PASS** otherwise.

## Non-compliant example
```hcl
resource "azurerm_postgresql_configuration" "log_connections" {
  name                = "log_connections"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "off"
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_configuration" "log_connections" {
  name                = "log_connections"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "on"   # was "off"
}
```

## Remediation steps
1. Set the `azurerm_postgresql_configuration` resource with `name = "log_connections"` to `value = "on"`.
2. In ARM/Bicep, set the nested `configurations` resource's `properties.value` to `"on"` for the `log_connections` parameter.
3. Ship the resulting logs to a centralized SIEM/Log Analytics workspace via diagnostic settings so connection audit trails are retained and searchable, not just written to ephemeral server logs.
4. Be aware `log_connections` slightly increases log volume proportional to connection churn — for high-connection-rate workloads, consider connection pooling (e.g., PgBouncer) to reduce noise while retaining the audit benefit.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerLogConnectionsEnabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/PostgreSQLServerLogConnectionsEnabled.py)
- [Azure Database for PostgreSQL server parameters](https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-servers)
