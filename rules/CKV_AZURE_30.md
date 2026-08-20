# CKV_AZURE_30: Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server

## Severity
**LOW** (score: 2.0/10)

Disabling checkpoint logging only reduces operational diagnostic detail for PostgreSQL performance tuning and has no direct bearing on confidentiality, integrity, or access control.

## Summary
This check ensures the PostgreSQL server configuration parameter `log_checkpoints` is turned on, so checkpoint activity is recorded in the server logs.

## Applicability
- **Frameworks:** Terraform, ARM, Bicep (via shared entities)
- **Resource types:** `Microsoft.DBforPostgreSQL/servers/configurations` (and generic `configurations` with `parent_type = Microsoft.DBforPostgreSQL/servers`), `azurerm_postgresql_configuration`

## Why it matters
Checkpoints are a core PostgreSQL internal operation that flushes dirty buffers to disk and truncates the write-ahead log; their timing and frequency have significant performance implications, and unusual checkpoint patterns (excessive frequency, long duration) are often the first visible sign of I/O contention, undersized WAL settings, or an ongoing incident (e.g., a runaway write workload, possibly from an attacker or a misbehaving job). Without `log_checkpoints = on`, this activity is invisible in the logs, making it much harder to diagnose performance degradation or correlate database-level anomalies with application-level incidents during forensic review or troubleshooting. This is primarily an operational-visibility/auditability control that supports incident response and reliability engineering.

## How Checkov evaluates this
**ARM check**: only applies when the resource `type` is `Microsoft.DBforPostgreSQL/servers/configurations` (or generic `configurations` with `parent_type == "Microsoft.DBforPostgreSQL/servers"`) and `name == "log_checkpoints"`. **PASS** if `properties.value` (case-insensitive) equals `"on"`; **FAIL** if it's set to anything else (e.g., `"off"`); returns **UNKNOWN** if the resource isn't the `log_checkpoints` configuration at all (i.e., the check doesn't apply/doesn't judge unrelated configuration parameters).

**Terraform check**: inspects the `azurerm_postgresql_configuration` resource's `name` and `value`. **FAIL** only if `name == "log_checkpoints"` and `value == "off"`; **PASS** in all other cases (including when the resource configures a different parameter entirely).

## Non-compliant example
```hcl
resource "azurerm_postgresql_configuration" "log_checkpoints" {
  name                = "log_checkpoints"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "off"
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_configuration" "log_checkpoints" {
  name                = "log_checkpoints"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "on"   # was "off"
}
```

## Remediation steps
1. Set the `azurerm_postgresql_configuration` resource with `name = "log_checkpoints"` to `value = "on"`.
2. In ARM/Bicep templates, set the nested `configurations` resource's `properties.value` to `"on"` for the `log_checkpoints` parameter.
3. Ensure your logging pipeline (Azure Monitor diagnostic settings / Log Analytics) actually captures PostgreSQL server logs, otherwise this setting alone won't provide visibility.
4. Applies equally to `azurerm_postgresql_flexible_server_configuration` if migrating to Flexible Server — check the equivalent resource/parameter name there.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerLogCheckpointsEnabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/PostgreSQLServerLogCheckpointsEnabled.py)
- [Azure Database for PostgreSQL server parameters](https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-servers)
