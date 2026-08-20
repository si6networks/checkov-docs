# CKV2_AZURE_57: Ensure PostgreSQL Flexible Server is configured with private endpoint

## Severity
**MEDIUM** (score: 5.0/10)

Without a private endpoint, a PostgreSQL Flexible Server is exposed to public network access, increasing the risk of unauthorized connection attempts and credential-stuffing/brute-force attacks against the database.

## Summary
This check verifies that every Azure Database for PostgreSQL Flexible Server has an associated Private Endpoint, so the database is not exposed to the public internet by default.

## Applicability
- **Terraform**: `azurerm_postgresql_flexible_server` (must be connected to an `azurerm_private_endpoint` resource)

This is a graph-based connection check, structurally identical to CKV2_AZURE_56 but for PostgreSQL instead of MySQL.

## Why it matters
A PostgreSQL Flexible Server without a private endpoint may be reachable over its public FQDN, relying solely on firewall rules and TLS/authentication to keep it safe. Firewall rules are configuration, and configuration drifts — an overly broad rule (e.g., `0.0.0.0`-`255.255.255.255`, or an "allow Azure services" rule) can silently expose the database. A private endpoint removes the public data-plane path entirely, giving the server a private IP inside your VNet and making network-layer isolation the default rather than something dependent on firewall rule hygiene. This materially reduces the blast radius of credential leaks and brute-force/enumeration attacks against the database port.

## How Checkov evaluates this
Implemented as a JSON graph query.

- FAIL: an `azurerm_postgresql_flexible_server` resource exists with no connected `azurerm_private_endpoint` resource.
- PASS: the flexible server is connected to at least one `azurerm_private_endpoint` resource.

## Non-compliant example
```hcl
resource "azurerm_postgresql_flexible_server" "example" {
  name                   = "example-pgflexserver"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  version                = "14"
  administrator_login    = "psqladmin"
  administrator_password = var.psql_admin_password
  storage_mb             = 32768
  sku_name               = "B_Standard_B1ms"
}
# No azurerm_private_endpoint associated -> FAILS
```

## Remediated example
```hcl
resource "azurerm_postgresql_flexible_server" "example" {
  name                   = "example-pgflexserver"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  version                = "14"
  administrator_login    = "psqladmin"
  administrator_password = var.psql_admin_password
  storage_mb             = 32768
  sku_name               = "B_Standard_B1ms"
}

# Added: private endpoint for the PostgreSQL Flexible Server
resource "azurerm_private_endpoint" "postgres_pe" {
  name                = "example-pgflexserver-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "example-pgflexserver-psc"
    private_connection_resource_id = azurerm_postgresql_flexible_server.example.id
    subresource_names              = ["postgresqlServer"]
    is_manual_connection           = false
  }
}
```

## Remediation steps
1. Create (or reuse) a subnet for private endpoints in your VNet.
2. Add an `azurerm_private_endpoint` resource whose `private_service_connection.private_connection_resource_id` points at the PostgreSQL Flexible Server.
3. Create/link a Private DNS Zone (`privatelink.postgres.database.azure.com`) to your VNet so clients resolve to the private IP transparently.
4. Set `public_network_access_enabled = false` on the server once the private endpoint path is confirmed working, to close the public network entirely.
5. Note: PostgreSQL Flexible Server also supports VNet-integrated deployment (no public IP at all) as an alternative network model — but this specific Checkov check looks for a private endpoint connection, so a VNet-integrated-only server without a private endpoint resource will still be flagged.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzurePostgreSQLFlexibleServerConfigPrivEndpt.json)
- [Azure Database for PostgreSQL Flexible Server networking documentation](https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking)
