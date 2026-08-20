# CKV2_AZURE_34: Ensure Azure SQL server firewall is not overly permissive
## Severity
**HIGH** (score: 7.5/10)

A SQL Server firewall rule of 0.0.0.0-0.0.0.0 is Azure's sentinel for 'allow all Azure-hosted services,' removing meaningful network-level restriction on inbound connections and leaving authentication as the sole control against any Azure-tenant attacker infrastructure.

## Summary
This check verifies that an Azure SQL (or MSSQL) server firewall rule is not scoped to the special `0.0.0.0`–`0.0.0.0` range, which represents the "allow all Azure services" catch-all rather than an intentionally scoped IP range.

## Applicability
- **IaC framework:** Terraform (graph-based attribute check)
- **Resource types involved:** `azurerm_sql_firewall_rule`, `azurerm_mssql_firewall_rule`

## Why it matters
Azure treats a firewall rule with both `start_ip_address` and `end_ip_address` set to `0.0.0.0` as a special sentinel meaning "allow access from any Azure service/resource within Azure," effectively removing IP-based restriction for anything running in Azure's IP space — not just your own resources. This is dramatically broader than most teams intend when writing such a rule, since it permits connections from any Azure tenant's resources, not merely the organization's own VNets or services. Combined with weak or reused SQL credentials, this rule turns the SQL server's authentication into the sole line of defense against literally any Azure-hosted attacker infrastructure, since the network layer imposes no meaningful restriction. It is one of the most common and consequential Azure SQL misconfigurations because it's easy to enable by accident (it's the underlying mechanism behind the "Allow Azure services" portal toggle) while looking, at a glance, like a narrowly scoped single-IP rule.

## How Checkov evaluates this
This is a **graph-based attribute check** — the two conditions are combined with **OR** (the rule passes if *either* holds):
1. `start_ip_address` **not equals** `"0.0.0.0"`.
2. `end_ip_address` **not equals** `"0.0.0.0"`.

Because of the OR, the check only FAILS when **both** `start_ip_address` and `end_ip_address` are exactly `"0.0.0.0"` simultaneously — the specific "allow all Azure services" sentinel value. Any genuinely scoped range (even a wide one, as long as it isn't literally `0.0.0.0`–`0.0.0.0`) passes this particular check.

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = "example-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}

# The special "allow all Azure services" sentinel range.
resource "azurerm_mssql_firewall_rule" "example" {
  name             = "AllowAllAzureServices"
  server_id        = azurerm_mssql_server.example.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}
```

## Remediated example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = "example-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}

# Fixed: scope to a known, specific range instead of the "allow all Azure" sentinel.
resource "azurerm_mssql_firewall_rule" "example" {
  name             = "allow-app-service-outbound"
  server_id        = azurerm_mssql_server.example.id
  start_ip_address = "20.51.12.0"
  end_ip_address   = "20.51.12.15"
}
```

## Remediation steps
1. Remove any `0.0.0.0`–`0.0.0.0` firewall rule (i.e., disable "Allow Azure services and resources to access this server" in the portal, or delete the equivalent Terraform rule).
2. Identify the actual known source IPs/ranges that legitimately need access (specific App Service outbound IPs, VPN gateway, office egress) and create narrowly scoped rules for those instead.
3. Prefer VNet-based access control: use `azurerm_mssql_virtual_network_rule` to allow specific subnets, or better, use a Private Endpoint (`azurerm_private_endpoint`) with `public_network_access_enabled = false` on the server to eliminate public firewall rules entirely.
4. If a first-party Azure service genuinely needs access (e.g., Azure Functions, Data Factory), prefer their managed-identity/VNet-integration options over the blanket "allow all Azure services" rule.
5. Audit existing servers for this sentinel rule, since it is often enabled unintentionally via the portal's convenience checkbox during initial setup.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureSQLserverNotOverlyPermissive.json)
- [Azure SQL Database and Azure Synapse IP firewall rules](https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure)
