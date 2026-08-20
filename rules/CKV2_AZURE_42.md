# CKV2_AZURE_42: Ensure Azure PostgreSQL server is configured with private endpoint

## Severity
**HIGH** (score: 7.0/10)

A PostgreSQL server without a private endpoint is more likely to be reachable over the public network, broadening exposure of a database service that typically stores sensitive application data.

## Summary
This check ensures that an Azure Database for PostgreSQL (single server) resource has an associated Azure Private Endpoint, so database traffic stays on the Microsoft backbone/private network rather than traversing the public internet.

## Applicability
- **IaC framework:** Terraform (graph-based connection check)
- **Resource type:** `azurerm_postgresql_server` (must be connected to an `azurerm_private_endpoint`)

## Why it matters
Without a private endpoint, a PostgreSQL server is reachable via its public FQDN, meaning it depends entirely on firewall rules (`azurerm_postgresql_firewall_rule`) or public-network-access toggles to prevent unauthorized connections. Public endpoints for database services are a common target for internet-wide scanning, credential-stuffing/brute-force attempts, and exploitation of any authentication misconfiguration, and a firewall rule can be inadvertently widened (e.g., `0.0.0.0-255.255.255.255` "Allow Azure services" or an overly broad CIDR) exposing the database to the entire internet. A private endpoint assigns the server a private IP address inside a VNet, removing public reachability entirely — connections must originate from within the VNet or a peered/VPN-connected network, eliminating the internet as an attack vector and satisfying network-isolation requirements common in PCI-DSS, HIPAA, and internal segmentation policies.

## How Checkov evaluates this
Graph-based JSON policy. It filters for `azurerm_postgresql_server` resources and PASSES only if that resource has a graph connection to an `azurerm_private_endpoint` resource (typically established via the private endpoint's `private_service_connection.private_connection_resource_id` referencing the PostgreSQL server, or via a `subresource_names = ["postgresqlServer"]` connection). If no such connection exists in the Terraform graph, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "example-psqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladmin"
  administrator_login_password = var.psql_password

  sku_name   = "GP_Gen5_4"
  version    = "11"
  storage_mb = 640000

  ssl_enforcement_enabled = true
  # no azurerm_private_endpoint associated with this server
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "example-psqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladmin"
  administrator_login_password = var.psql_password

  sku_name   = "GP_Gen5_4"
  version    = "11"
  storage_mb = 640000

  ssl_enforcement_enabled = true
}

resource "azurerm_private_endpoint" "psql" {
  name                = "example-psql-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "psql-privateserviceconnection"
    private_connection_resource_id = azurerm_postgresql_server.example.id
    subresource_names              = ["postgresqlServer"]
    is_manual_connection            = false
  }
}
```

## Remediation steps
1. Create an `azurerm_private_endpoint` resource in the target VNet/subnet, with a `private_service_connection` block pointing at the PostgreSQL server's ID and `subresource_names = ["postgresqlServer"]`.
2. Ensure a corresponding Private DNS Zone (`privatelink.postgres.database.azure.com`) is linked to the VNet so clients resolve the server's FQDN to the private IP.
3. Once the private endpoint is confirmed working, disable public network access on the server (`public_network_access_enabled = false`, where supported) and remove overly broad firewall rules.
4. Note: Azure Database for PostgreSQL Single Server is being retired in favor of Flexible Server — consider migrating and using Flexible Server's VNet-integrated private access instead.
5. Adding a private endpoint after the fact does not require server downtime, but DNS propagation and client reconfiguration should be planned.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzurePostgreSQLserverConfigPrivEndpt.json)
- [Azure Private Link for PostgreSQL documentation](https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-data-access-security-private-link)
