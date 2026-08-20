# CKV_AZURE_53: Ensure 'public network access enabled' is set to 'False' for mySQL servers
## Severity
**HIGH** (score: 7.5/10)

A publicly reachable MySQL server is directly exposed to internet-wide brute-force and reconnaissance against a data-tier resource, removing the network-layer barrier that would otherwise force an attacker to first pivot inside the perimeter.

## Summary
This check fails when an Azure MySQL server (or flexible server) is configured to allow public network access, ensuring the database is only reachable through private/virtual network connectivity.

## Applicability
Applies to Terraform (`azurerm_mysql_server`), ARM templates, and Bicep, for the resource types `Microsoft.DBforMySQL/servers` and `Microsoft.DBforMySQL/flexibleServers`.

## Why it matters
An Azure Database for MySQL server with public network access enabled exposes its endpoint to the internet. Even though authentication (username/password) is still required, this dramatically increases the attack surface: it opens the server to brute-force credential attacks, exploitation of MySQL protocol vulnerabilities, and reconnaissance/scanning from any host on the internet. Database servers are high-value targets because they hold sensitive application data directly; a compromised credential combined with public reachability turns a single leaked password into a full data breach, whereas requiring private network/VNet access means an attacker must first pivot into the network perimeter, adding a meaningful layer of defense-in-depth. Disabling public network access forces all traffic through private endpoints, VNet service endpoints, or VNet rules, which is the Azure-recommended pattern for data-tier resources.

## How Checkov evaluates this
- For ARM/Bicep: the check reads `properties/publicNetworkAccess` on `Microsoft.DBforMySQL/servers` (or `properties/network/publicNetworkAccess` on `Microsoft.DBforMySQL/flexibleServers`) and PASSES only if the value is `"disabled"` or `"Disabled"`; anything else (including the field being absent, depending on base-class default handling) FAILS.
- For Terraform: it inspects the `public_network_access_enabled` attribute on `azurerm_mysql_server` and expects it to be exactly `false`. If set to `true` or omitted (provider default is `true`), the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example-mysqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "B_Gen5_2"
  version  = "5.7"

  administrator_login          = "mysqladminun"
  administrator_login_password = var.mysql_password

  ssl_enforcement_enabled          = true
  public_network_access_enabled    = true
}
```

## Remediated example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example-mysqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "B_Gen5_2"
  version  = "5.7"

  administrator_login          = "mysqladminun"
  administrator_login_password = var.mysql_password

  ssl_enforcement_enabled          = true
  public_network_access_enabled    = false  # blocks public endpoint access
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess: "Disabled"` (ARM/Bicep) on the MySQL server resource.
2. Provision a Private Endpoint (`azurerm_private_endpoint` targeting the MySQL server's `privateLinkServiceConnection` subresource `mysqlServer`) or configure VNet Rules so internal consumers can still reach the database.
3. Update connection strings/DNS to resolve to the private endpoint's private IP (via Azure Private DNS zone `privatelink.mysql.database.azure.com`).
4. Note `azurerm_mysql_server` is deprecated in favor of `azurerm_mysql_flexible_server`; for flexible servers use `network { public_network_access_enabled = false }`.
5. Test application connectivity from within the VNet/peered network before removing any temporary public access used during migration.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/MySQLPublicAccessDisabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLPublicAccessDisabled.py)
- [Azure docs: Deny public network access – Azure Database for MySQL](https://learn.microsoft.com/en-us/azure/mysql/single-server/concepts-data-access-security-private-link)
