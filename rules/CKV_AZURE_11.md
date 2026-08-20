# CKV_AZURE_11: Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)
## Severity
**CRITICAL** (score: 9.0/10)

A SQL Server firewall rule permitting ingress from 0.0.0.0/0 exposes the database service to the entire internet, enabling brute-force login attempts and exploitation attempts against any reachable database.

## Summary
This check ensures that SQL server/database firewall rules do not create a rule spanning the entire IP address space (`0.0.0.0` – `255.255.255.255`), which is the equivalent of allowing access from any IP address on the internet.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_mariadb_firewall_rule`, `azurerm_sql_firewall_rule`, `azurerm_postgresql_firewall_rule`, `azurerm_mysql_firewall_rule`, `azurerm_mysql_flexible_server_firewall_rule`, `azurerm_mssql_firewall_rule`
- **ARM/Bicep**: `Microsoft.Sql/servers` (specifically nested `firewallRules`/`firewallrules` sub-resources)

## Why it matters
Azure SQL and related managed database services (PostgreSQL, MySQL, MariaDB) restrict network access via server-level firewall rules. A firewall rule with a start IP of `0.0.0.0` and an end IP of `255.255.255.255` — Azure's documented shorthand/equivalent for "allow all IPs" — disables the network-layer protection entirely, meaning any host on the internet can attempt to connect to the database engine (subject only to authentication). This dramatically increases exposure to brute-force login attempts, exploitation of any authentication weaknesses (weak passwords, leaked credentials), and vulnerability scanning against the database engine itself. Scoping firewall rules to specific, known IP ranges (application servers, VPN egress, admin workstations) or using VNet/Private Link is essential to keep the database off the open internet's direct reach.

## How Checkov evaluates this
- **Terraform**: for each of the supported firewall-rule resource types, the check looks at `start_ip_address` and `end_ip_address`. If `start_ip_address` is exactly `"0.0.0.0"` or `"0.0.0.0/0"` **and** `end_ip_address` is exactly `"255.255.255.255"`, the check **FAILS**. Any other IP range (even a very broad but non-maximal one) **PASSES**.
- **ARM**: walks the `resources` array of a `Microsoft.Sql/servers` resource looking for nested resources of type `Microsoft.Sql/servers/firewallRules` (or `firewallRules`/`firewallrules`). For each such nested resource, if `properties.startIpAddress` is `"0.0.0.0"`/`"0.0.0.0/0"` and `properties.endIpAddress` is `"255.255.255.255"`, the check **FAILS**; otherwise it **PASSES**.

Note this check only flags the specific full-range pattern — it does not flag merely broad ranges that don't span the entire address space.

## Non-compliant example
```hcl
resource "azurerm_sql_firewall_rule" "bad_example" {
  name                = "allow-all"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "255.255.255.255"
}
```

## Remediated example
```hcl
resource "azurerm_sql_firewall_rule" "good_example" {
  name                = "allow-office-network"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  # Fix: scope the rule to a specific, known IP range instead of the whole internet
  start_ip_address    = "203.0.113.0"
  end_ip_address      = "203.0.113.255"
}
```

## Remediation steps
1. Locate any `*_firewall_rule` resources whose `start_ip_address`/`end_ip_address` span `0.0.0.0`–`255.255.255.255`.
2. Replace them with narrow, specific ranges covering only the actual source IPs that need access (application tier, VPN gateway, bastion, CI/CD runner egress IPs).
3. Prefer eliminating public firewall rules entirely in favor of VNet service endpoints (`azurerm_mssql_virtual_network_rule` / equivalents) or Private Link, so the database is not exposed via any public IP path.
4. If Azure services (e.g., App Service, Functions) need connectivity, use the specific "Allow Azure services" toggle where available rather than an all-IPs rule, and prefer VNet integration for those services when possible.
5. Audit existing firewall rule sets after remediation with `az sql server firewall-rule list` (or the equivalent for other engines) to confirm no residual all-IP rule remains.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SQLServerNoPublicAccess.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerNoPublicAccess.py)
- [Azure docs: Azure SQL Database and Azure Synapse IP firewall rules](https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure)
