# CKV2_AZURE_56: Ensure Azure MySQL Flexible Server is configured with private endpoint

## Severity
**MEDIUM** (score: 5.0/10)

Without a private endpoint, an Azure MySQL Flexible Server is reachable over the public network path, materially widening the attack surface for a database that typically holds sensitive application data.

## Summary
This check verifies that every Azure Database for MySQL Flexible Server has an associated Private Endpoint, so the database is not reachable only through public networking paths.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_mysql_flexible_server` (must be connected to an `azurerm_private_endpoint` resource)

This is a graph-based connection check.

## Why it matters
By default, an Azure MySQL Flexible Server can be reachable over the public internet (subject to firewall rules), which puts the database directly in scope for internet-wide scanning, brute-force login attempts, and any misconfigured firewall rule becoming a full public exposure. A Private Endpoint places the server's data-plane endpoint inside your VNet, giving it a private IP address reachable only from your network (or peered/VPN-connected networks), eliminating the public attack surface entirely and satisfying network-isolation requirements common in PCI-DSS and internal security baselines.

## How Checkov evaluates this
Implemented as a JSON graph query.

- FAIL: an `azurerm_mysql_flexible_server` resource exists with no connected `azurerm_private_endpoint` resource in the configuration graph.
- PASS: the flexible server is connected to at least one `azurerm_private_endpoint` resource (the private endpoint's target sub-resource type isn't further validated by this specific check — the mere connection is sufficient).

## Non-compliant example
```hcl
resource "azurerm_mysql_flexible_server" "example" {
  name                   = "example-mysqlfs"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  administrator_login    = "mysqladmin"
  administrator_password = var.mysql_admin_password
  sku_name               = "B_Standard_B1ms"
}
# No azurerm_private_endpoint associated with this server -> FAILS
```

## Remediated example
```hcl
resource "azurerm_mysql_flexible_server" "example" {
  name                   = "example-mysqlfs"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  administrator_login    = "mysqladmin"
  administrator_password = var.mysql_admin_password
  sku_name               = "B_Standard_B1ms"
}

# Added: private endpoint for the MySQL Flexible Server
resource "azurerm_private_endpoint" "mysql_pe" {
  name                = "example-mysqlfs-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "example-mysqlfs-psc"
    private_connection_resource_id = azurerm_mysql_flexible_server.example.id
    subresource_names              = ["mysqlServer"]
    is_manual_connection           = false
  }
}
```

## Remediation steps
1. Create a dedicated subnet with private endpoint network policies enabled (or disabled per Azure's requirements for the resource type).
2. Add an `azurerm_private_endpoint` resource referencing the MySQL Flexible Server's ID via `private_service_connection.private_connection_resource_id`.
3. Add a corresponding Private DNS Zone (`privatelink.mysql.database.azure.com`) linked to your VNet so clients resolve the private IP.
4. Restrict or remove public network access on the server (`public_network_access_enabled = false`) once the private endpoint is validated as working, to fully close the public path.
5. Note: Azure MySQL Flexible Server supports VNet-integration as an alternative to private endpoints in some deployment modes — Checkov's graph check here specifically looks for a private endpoint connection, so VNet-integrated-only deployments without a private endpoint will still fail this check.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureMySQLFlexibleServerConfigPrivEndpt.json)
- [Azure Database for MySQL Flexible Server networking documentation](https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-networking)
