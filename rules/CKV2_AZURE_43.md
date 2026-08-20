# CKV2_AZURE_43: Ensure Azure MariaDB server is configured with private endpoint

## Severity
**HIGH** (score: 7.0/10)

A MariaDB server without a private endpoint is more likely to be reachable over the public network, broadening exposure of a database service that typically stores sensitive application data.

## Summary
This check ensures that an Azure Database for MariaDB server has an associated Azure Private Endpoint, so database traffic stays on the Microsoft backbone/private network instead of traversing the public internet.

## Applicability
- **IaC framework:** Terraform (graph-based connection check)
- **Resource type:** `azurerm_mariadb_server` (must be connected to an `azurerm_private_endpoint`)

## Why it matters
A MariaDB server without a private endpoint relies solely on server-level firewall rules and public network access settings to keep it away from unauthorized clients. Publicly reachable database endpoints are routinely scanned by attackers looking for weak credentials, unpatched database engines, or misconfigured firewall rules (e.g., an accidentally broad `0.0.0.0/0` allow rule). Even with SSL enforced (see CKV2_AZURE_37) and strong credentials, a public endpoint remains a viable target for denial-of-service, brute-force login attempts, and exploitation of any future authentication vulnerability. A private endpoint removes the server from the public address space entirely — giving it a private IP inside your VNet — so only clients within the VNet (or peered/VPN-connected networks) can reach it at all, regardless of credentials.

## How Checkov evaluates this
Graph-based JSON policy. It filters for `azurerm_mariadb_server` resources and PASSES only if the resource has a graph connection to an `azurerm_private_endpoint` resource (established via the private endpoint's `private_service_connection` referencing the MariaDB server, typically with `subresource_names = ["mariadbServer"]`). If no such connection exists, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_mariadb_server" "example" {
  name                = "example-mariadb"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadmin"
  administrator_login_password = var.mariadb_password

  sku_name   = "B_Gen5_2"
  storage_mb = 51200
  version    = "10.2"

  ssl_enforcement_enabled = true
  # no azurerm_private_endpoint associated with this server
}
```

## Remediated example
```hcl
resource "azurerm_mariadb_server" "example" {
  name                = "example-mariadb"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadmin"
  administrator_login_password = var.mariadb_password

  sku_name   = "B_Gen5_2"
  storage_mb = 51200
  version    = "10.2"

  ssl_enforcement_enabled = true
}

resource "azurerm_private_endpoint" "mariadb" {
  name                = "example-mariadb-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "mariadb-privateserviceconnection"
    private_connection_resource_id = azurerm_mariadb_server.example.id
    subresource_names              = ["mariadbServer"]
    is_manual_connection            = false
  }
}
```

## Remediation steps
1. Create an `azurerm_private_endpoint` resource with a `private_service_connection` block pointing at the MariaDB server's ID and `subresource_names = ["mariadbServer"]`.
2. Link a Private DNS Zone (`privatelink.mariadb.database.azure.com`) to the VNet so clients resolve the server's FQDN to its private IP.
3. After confirming private connectivity works, disable public network access on the server and tighten/remove firewall rules that permitted broad access.
4. Note: Azure Database for MariaDB is on a Microsoft-announced retirement path — plan a migration to Azure Database for MySQL Flexible Server, which has more first-class private networking support.
5. Adding the private endpoint does not require recreating the server, but plan for DNS propagation and client reconfiguration.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureMariaDBserverConfigPrivEndpt.json)
- [Azure Private Link for MariaDB documentation](https://learn.microsoft.com/en-us/azure/mariadb/concepts-data-access-security-private-link)
