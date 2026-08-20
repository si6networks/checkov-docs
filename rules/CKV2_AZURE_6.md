# CKV2_AZURE_6: Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled

## Severity
**HIGH** (score: 7.5/10)

Allowing broad Azure-services access (effectively an any-Azure-tenant 0.0.0.0 firewall rule) to a PostgreSQL server significantly expands the network exposure of a sensitive data store beyond the intended trust boundary.

## Summary
This check verifies that a SQL/PostgreSQL server's firewall does not have the special "Allow access to Azure services" rule enabled (represented in Terraform as a firewall rule spanning `0.0.0.0` to `0.0.0.0`).

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_sql_server` (evaluated in connection with any `azurerm_sql_firewall_rule` resources attached to it)

This is a graph-based connection/attribute check. Despite the policy title mentioning PostgreSQL, the underlying entities checked are the legacy `azurerm_sql_server`/`azurerm_sql_firewall_rule` (Azure SQL) resource types.

## Why it matters
Azure represents the "Allow access to Azure services" toggle as a firewall rule with both start and end IP set to `0.0.0.0`. Enabling it means the server can be reached from any Azure resource in any subscription, not just your own — including resources belonging to other Azure customers. This dramatically widens the server's effective attack surface: any compromised or malicious workload running anywhere in Azure could attempt to connect to your database, relying only on credentials/authentication as the remaining control layer. Disabling this rule and instead using specific firewall rules, VNet service endpoints, or private endpoints keeps network-layer access scoped to only the resources that actually need it.

## How Checkov evaluates this
Implemented as a JSON graph query.

- PASS: the `azurerm_sql_server` has no connected `azurerm_sql_firewall_rule` resources at all.
- PASS: it has connected firewall rules, but none of them has both `start_ip_address == "0.0.0.0"` and... — specifically, the check requires that for every connected firewall rule, `start_ip_address != "0.0.0.0"` AND `end_ip_address != "0.0.0.0"`.
- FAIL: any connected `azurerm_sql_firewall_rule` has `start_ip_address == "0.0.0.0"` and `end_ip_address == "0.0.0.0"` (the Azure convention for "Allow access to Azure services").

## Non-compliant example
```hcl
resource "azurerm_sql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}

resource "azurerm_sql_firewall_rule" "allow_azure_services" {
  name                = "AllowAllWindowsAzureIps"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "0.0.0.0"   # FAILS: allows any Azure resource to connect
}
```

## Remediated example
```hcl
resource "azurerm_sql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}

# Removed the 0.0.0.0-0.0.0.0 rule; scope access to a specific known range instead
resource "azurerm_sql_firewall_rule" "office_ip" {
  name                = "AllowOfficeIp"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  start_ip_address    = "203.0.113.10"
  end_ip_address      = "203.0.113.10"
}
```

## Remediation steps
1. Remove any `azurerm_sql_firewall_rule` with `start_ip_address = "0.0.0.0"` and `end_ip_address = "0.0.0.0"`.
2. Replace broad access with specific, minimal IP ranges for the clients/services that genuinely need access.
3. For services that must reach the database from within Azure, use VNet service endpoints (`azurerm_sql_virtual_network_rule`) or a private endpoint instead of the blanket "Allow Azure services" rule.
4. If migrating to the newer `azurerm_mssql_server`/`azurerm_mssql_firewall_rule` resources, apply the equivalent restriction there (Checkov has related checks for those resource types).
5. Test connectivity after tightening rules — legitimate integrations (e.g., Azure Data Factory, App Service) may need explicit private endpoint or VNet rule configuration to keep working.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AccessToPostgreSQLFromAzureServicesIsDisabled.json)
- [Azure SQL Database firewall rules documentation](https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure)
