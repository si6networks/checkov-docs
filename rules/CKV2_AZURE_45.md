# CKV2_AZURE_45: Ensure Microsoft SQL server is configured with private endpoint

## Severity
**HIGH** (score: 7.0/10)

A Microsoft SQL server without a private endpoint is more likely to be reachable over the public network, broadening exposure of a database service that typically stores sensitive application data.

## Summary
This check ensures that an Azure SQL server (`azurerm_mssql_server`) has an associated Azure Private Endpoint, so database traffic stays on the Microsoft backbone/private network instead of traversing the public internet.

## Applicability
- **IaC framework:** Terraform (graph-based connection check)
- **Resource type:** `azurerm_mssql_server` (must be connected to an `azurerm_private_endpoint`)

## Why it matters
An Azure SQL logical server reachable via its public FQDN depends on firewall rules and the `public_network_access_enabled` setting as its only network-layer defense. Public SQL endpoints are a high-value target — attackers routinely scan for exposed SQL ports, attempt credential-stuffing against `sqladmin`-style accounts, and probe for authentication bypass or injection vulnerabilities. A single overly broad firewall rule (e.g., allowing `0.0.0.0` for the "Allow Azure services" toggle, which lets any Azure tenant's resources attempt a connection) can expose sensitive production data. A private endpoint assigns the server a private IP inside your VNet, so only clients within that VNet (or connected networks) can reach it, structurally eliminating internet-based attacks against the SQL endpoint regardless of firewall rule mistakes.

## How Checkov evaluates this
Graph-based JSON policy. It filters for `azurerm_mssql_server` resources and PASSES only if the resource has a graph connection to an `azurerm_private_endpoint` resource (established via the private endpoint's `private_service_connection` referencing the SQL server, typically with `subresource_names = ["sqlServer"]`). If no such connection exists, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_password
  # no azurerm_private_endpoint associated with this server
}
```

## Remediated example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_password
}

resource "azurerm_private_endpoint" "sql" {
  name                = "example-sql-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "sql-privateserviceconnection"
    private_connection_resource_id = azurerm_mssql_server.example.id
    subresource_names              = ["sqlServer"]
    is_manual_connection            = false
  }
}
```

## Remediation steps
1. Create an `azurerm_private_endpoint` resource with a `private_service_connection` block pointing at the SQL server's ID and `subresource_names = ["sqlServer"]`.
2. Link a Private DNS Zone (`privatelink.database.windows.net`) to the VNet so clients resolve the server's FQDN to the private IP.
3. After validating connectivity through the private endpoint, set `public_network_access_enabled = false` on the SQL server and remove/tighten firewall rules that previously allowed public access.
4. Ensure any Azure services that need to reach the database (App Service, Functions, Data Factory, etc.) are VNet-integrated or peered so they retain connectivity after public access is disabled.
5. This is an additive change (does not require server recreation), but plan for DNS propagation and downstream application reconfiguration.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureMSSQLserverConfigPrivEndpt.json)
- [Azure SQL Private Link documentation](https://learn.microsoft.com/en-us/azure/azure-sql/database/private-endpoint-overview)
