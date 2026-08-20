# CKV_AZURE_48: Ensure 'public network access enabled' is set to 'False' for MariaDB servers

## Severity
**HIGH** (score: 8.0/10)

Enabling public network access on a MariaDB server exposes the database endpoint directly to the internet, dramatically increasing the attack surface for credential brute-forcing and exploitation of database-layer vulnerabilities.

## Summary
This check verifies that an Azure Database for MariaDB server has public network access disabled, so the database is only reachable via private connectivity (VNet service endpoints, VNet rules, or Private Link) rather than the public internet.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_mariadb_server`
- **ARM templates**: `Microsoft.DBforMariaDB/servers`
- **Bicep**: `Microsoft.DBforMariaDB/servers`

## Why it matters
A MariaDB server with public network access enabled is reachable from the internet by IP/hostname, relying entirely on firewall rules and authentication to prevent unauthorized access. This significantly increases attack surface: it becomes a target for internet-wide credential-stuffing and brute-force scanning against the database port, exposes the server to any future firewall misconfiguration (an overly broad `0.0.0.0/0` rule, or a rule left over from testing), and removes the network-layer defense-in-depth that private connectivity provides. Disabling public access forces all traffic through private networking (VNet peering, VNet service endpoints, or Private Link), meaning a compromised credential or an application-layer vulnerability alone is not sufficient for an external attacker to reach the database — they would also need a foothold inside the private network.

## How Checkov evaluates this
Implemented as a generic value check:
- **ARM**: Inspects `properties.publicNetworkAccess`. PASSES only if the value is exactly `"Disabled"`.
- **Terraform**: Inspects `public_network_access_enabled`. PASSES only if the value is `false`.

## Non-compliant example
```hcl
resource "azurerm_mariadb_server" "example" {
  name                = "example-mariadb"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadmin"
  administrator_login_password = var.admin_password

  sku_name   = "B_Gen5_2"
  version    = "10.2"
  storage_mb = 5120

  public_network_access_enabled = true
  ssl_enforcement_enabled       = true
}
```

## Remediated example
```hcl
resource "azurerm_mariadb_server" "example" {
  name                = "example-mariadb"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadmin"
  administrator_login_password = var.admin_password

  sku_name   = "B_Gen5_2"
  version    = "10.2"
  storage_mb = 5120

  public_network_access_enabled = false
  ssl_enforcement_enabled       = true
}

resource "azurerm_mariadb_virtual_network_rule" "example" {
  name                = "allow-app-subnet"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mariadb_server.example.name
  subnet_id           = azurerm_subnet.app.id
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` on the `azurerm_mariadb_server` resource, or `properties.publicNetworkAccess = "Disabled"` in ARM/Bicep.
2. Provision private connectivity for legitimate clients: `azurerm_mariadb_virtual_network_rule` for VNet-based access, or a Private Endpoint if your environment/tier supports it.
3. Verify existing firewall rules (`azurerm_mariadb_firewall_rule`) — disabling public network access supersedes IP-based firewall rules, so those become ineffective/unnecessary once this is set.
4. Test connectivity from all legitimate application subnets before applying to production, since this is a breaking change for any client connecting over the public endpoint.
5. Consider migration planning: Azure Database for MariaDB is on a retirement path in favor of MySQL/PostgreSQL Flexible Server, which have their own (generally improved) private networking models.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/MariaDBPublicAccessDisabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MariaDBPublicAccessDisabled.py)
- [Azure Database for MariaDB networking documentation](https://learn.microsoft.com/en-us/azure/mariadb/concepts-data-access-security-vnet)
