# CKV2_AZURE_26: Ensure Azure PostgreSQL Flexible server is not configured with overly permissive network access
## Severity
**CRITICAL** (score: 9.0/10)

A PostgreSQL Flexible Server firewall rule spanning the full 0.0.0.0-255.255.255.255 IPv4 range makes the database directly reachable from any host on the public internet, bypassing network-level access control entirely.

## Summary
This check verifies that firewall rules on an Azure Database for PostgreSQL Flexible Server do not open the entire IPv4 address space (`0.0.0.0` to `255.255.255.255`) to the database.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based attribute check)
- **Resource type involved:** `azurerm_postgresql_flexible_server_firewall_rule`

## Why it matters
A PostgreSQL Flexible Server firewall rule spanning the full IP range effectively makes the database reachable from anywhere on the internet, bypassing network-level access control entirely. Combined with any weak credential (default/reused passwords, leaked connection strings, or brute-forceable authentication), this exposes the database to direct attack from any host worldwide — a very common pattern in mass internet scanning campaigns that specifically hunt for exposed database ports (5432/TCP). Databases holding customer or business-critical data with a fully open firewall are routinely discovered and compromised within hours of misconfiguration, well before a human notices.

## How Checkov evaluates this
This is a **graph-based attribute check** with two independent conditions combined with AND:
1. `start_ip_address` must **not equal** `"0.0.0.0"`.
2. `end_ip_address` must **not equal** `"255.255.255.255"`.

A firewall rule FAILS only if it simultaneously has `start_ip_address = 0.0.0.0` AND `end_ip_address = 255.255.255.255` — i.e., a rule that spans the entire address space. Rules with narrower (even if still broad) ranges pass this specific check.

## Non-compliant example
```hcl
resource "azurerm_postgresql_flexible_server" "example" {
  name                   = "example-psqlflexibleserver"
  resource_group_name    = "example-rg"
  location               = "eastus"
  version                = "14"
  administrator_login    = "psqladmin"
  administrator_password = var.psql_admin_password
  sku_name               = "GP_Standard_D2s_v3"
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "example" {
  name             = "allow-all"
  server_id        = azurerm_postgresql_flexible_server.example.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_flexible_server" "example" {
  name                   = "example-psqlflexibleserver"
  resource_group_name    = "example-rg"
  location               = "eastus"
  version                = "14"
  administrator_login    = "psqladmin"
  administrator_password = var.psql_admin_password
  sku_name               = "GP_Standard_D2s_v3"
}

# Fixed: scope the firewall rule to a specific, known office/VPN egress range.
resource "azurerm_postgresql_flexible_server_firewall_rule" "example" {
  name             = "allow-corp-network"
  server_id        = azurerm_postgresql_flexible_server.example.id
  start_ip_address = "203.0.113.0"
  end_ip_address   = "203.0.113.255"
}
```

## Remediation steps
1. Replace any `0.0.0.0`–`255.255.255.255` firewall rule with narrowly scoped IP ranges representing known, trusted source addresses (corporate egress IPs, VPN gateways, bastion hosts).
2. Prefer eliminating public firewall rules entirely in favor of `azurerm_postgresql_flexible_server` with `public_network_access_enabled = false` plus a Private Endpoint / VNet integration for internal-only access.
3. If broad access is genuinely required (e.g., a SaaS integration with dynamic IPs), work with the vendor for published IP ranges rather than allowing the entire internet.
4. Audit existing deployments for any legacy "allow all" rules created during initial testing that were never removed before going to production.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzurePostgreSQLFlexServerNotOverlyPermissive.json)
- [Azure Database for PostgreSQL Flexible Server networking](https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking)
