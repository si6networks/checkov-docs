# CKV2_AZURE_44: Ensure Azure MySQL server is configured with private endpoint

## Severity
**HIGH** (score: 7.0/10)

A MySQL server without a private endpoint is more likely to be reachable over the public network, broadening exposure of a database service that typically stores sensitive application data.

## Summary
This check ensures that an Azure Database for MySQL server has an associated Azure Private Endpoint, so database traffic stays on the Microsoft backbone/private network instead of traversing the public internet.

## Applicability
- **IaC framework:** Terraform (graph-based connection check)
- **Resource type:** `azurerm_mysql_server` (must be connected to an `azurerm_private_endpoint`)

## Why it matters
A MySQL server exposed via a public endpoint depends entirely on firewall rules and network-access settings to keep unauthorized clients out. Public database endpoints are constantly probed by internet-wide scanners for weak/default credentials, known engine CVEs, and misconfigured firewall exceptions (a common real-world mistake is a firewall rule range that's broader than intended, or the "Allow access to Azure services" toggle which permits any Azure tenant's resources to attempt a connection). Removing the public endpoint via a private endpoint eliminates this entire class of exposure: the server gets a private IP inside your VNet, reachable only from within that VNet or networks connected to it, so credential-based attacks from the open internet are structurally impossible rather than merely mitigated by firewall configuration.

## How Checkov evaluates this
Graph-based JSON policy. It filters for `azurerm_mysql_server` resources and PASSES only if the resource has a graph connection to an `azurerm_private_endpoint` resource (established via the private endpoint's `private_service_connection` referencing the MySQL server, typically with `subresource_names = ["mysqlServer"]`). If no such connection exists in the Terraform configuration graph, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example-mysqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mysqladmin"
  administrator_login_password = var.mysql_password

  sku_name   = "GP_Gen5_4"
  version    = "5.7"
  storage_mb = 51200

  ssl_enforcement_enabled = true
  # no azurerm_private_endpoint associated with this server
}
```

## Remediated example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example-mysqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mysqladmin"
  administrator_login_password = var.mysql_password

  sku_name   = "GP_Gen5_4"
  version    = "5.7"
  storage_mb = 51200

  ssl_enforcement_enabled = true
}

resource "azurerm_private_endpoint" "mysql" {
  name                = "example-mysql-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "mysql-privateserviceconnection"
    private_connection_resource_id = azurerm_mysql_server.example.id
    subresource_names              = ["mysqlServer"]
    is_manual_connection            = false
  }
}
```

## Remediation steps
1. Create an `azurerm_private_endpoint` resource with a `private_service_connection` block pointing at the MySQL server's ID and `subresource_names = ["mysqlServer"]`.
2. Link a Private DNS Zone (`privatelink.mysql.database.azure.com`) to the VNet so clients resolve the server's FQDN to its private IP.
3. After validating private connectivity, disable public network access and remove/tighten firewall rules that allowed broader access.
4. Note: Azure Database for MySQL Single Server is retired/being retired in favor of Flexible Server, which supports VNet integration natively — consider migrating.
5. This change does not require server recreation, but plan for DNS propagation delays and client-side reconfiguration during rollout.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureMySQLserverConfigPrivEndpt.json)
- [Azure Private Link for MySQL documentation](https://learn.microsoft.com/en-us/azure/mysql/single-server/concepts-data-access-security-private-link)
