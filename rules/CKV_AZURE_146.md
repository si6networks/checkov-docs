# CKV_AZURE_146: Ensure server parameter 'log_retention' is set to 'ON' for PostgreSQL Database Server
## Severity
**LOW** (score: 2.0/10)

Disabling the `log_retention` server parameter removes an audit-logging control on PostgreSQL, hampering detection and forensic investigation of suspicious database activity, though it does not itself grant access or expose data.

## Summary
This check ensures the `log_retention` server configuration parameter for an Azure Database for PostgreSQL (single server) is not turned off, so query/connection logs are retained rather than discarded.

## Applicability
- **Terraform**: `azurerm_postgresql_configuration` resource, where `name = "log_retention"`.

## Why it matters
`log_retention` controls whether PostgreSQL's log files are retained on the server for the configured retention window versus disabled entirely. If this parameter is turned `off`, database activity logs — which are essential for detecting anomalous queries, diagnosing performance issues, and providing an audit trail during incident response or forensic investigation — are not retained. In a security incident (e.g., suspected SQL injection, unauthorized data access, or an insider threat), the absence of retained logs removes the primary evidence trail needed to determine what happened, when, and by whom, and can also violate compliance requirements (e.g. PCI-DSS, SOC 2) that mandate log retention for database systems handling sensitive data.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` (not a simple value check) that only inspects `azurerm_postgresql_configuration` resources. It reads `conf['name'][0]` and `conf['value'][0]`; the check FAILS specifically when `name == 'log_retention'` and `value == 'off'`. Any other configuration name is implicitly out of scope for this specific resource instance (the resource represents a single named/valued parameter), and any value other than `'off'` for `log_retention` (e.g. `'on'`) PASSES.

## Non-compliant example
```hcl
resource "azurerm_postgresql_configuration" "example" {
  name                = "log_retention"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "off"  # FAILS -- logs are not retained
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_configuration" "example" {
  name                = "log_retention"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "on"  # server logs are retained
}
```

## Remediation steps
1. Set the `azurerm_postgresql_configuration` resource with `name = "log_retention"` to `value = "on"` (or an appropriate day-count value if your target parameter format expects a retention duration rather than on/off — verify against the current Azure PostgreSQL single-server parameter documentation, since parameter formats can differ by parameter).
2. Note: Azure Database for PostgreSQL **single server** is a deprecated/retiring SKU family — for new deployments, prefer `azurerm_postgresql_flexible_server` and its equivalent logging configuration (`azurerm_postgresql_flexible_server_configuration` with the relevant `logfiles.retention_days`/`log_retention_days`-equivalent parameter), since this specific check only targets the legacy single-server resource type.
3. Pair log retention with forwarding logs to a centralized destination (Log Analytics workspace, Storage Account, or Event Hub via diagnostic settings) so logs survive beyond the server's local retention window and are searchable/alertable.
4. Verify the retention duration configured meets your organization's compliance/audit requirements, not just that logging is toggled on.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerLogRetentionEnabled.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-server-logs
