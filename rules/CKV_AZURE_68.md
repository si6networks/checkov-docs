# CKV_AZURE_68: Ensure that PostgreSQL server disables public network access
## Severity
**HIGH** (score: 7.5/10)

A publicly reachable PostgreSQL server is directly exposed to internet-wide brute-force and reconnaissance against a data-tier resource, removing the network-layer barrier that would otherwise require an attacker to first breach the perimeter.

## Summary
This check fails when an Azure Database for PostgreSQL (single) server is configured to allow public network access, exposing the database endpoint to the internet instead of restricting it to private/VNet connectivity.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

Applies to Terraform (`azurerm_postgresql_server`), ARM templates, and Bicep, for the resource type `Microsoft.DBforPostgreSQL/servers`.

## Why it matters
As with other managed database services, a PostgreSQL server reachable from the public internet is exposed to continuous automated scanning, brute-force login attempts, and exploitation of any PostgreSQL protocol or extension vulnerabilities without requiring the attacker to first gain a network foothold. Databases typically hold an organization's most sensitive structured data, so any credential compromise (weak password, leaked connection string, SQL injection leading to extracted credentials) becomes immediately and directly exploitable when the server is publicly reachable. Disabling public network access and requiring private endpoints or VNet integration adds a meaningful network-layer barrier: an attacker must first compromise something inside the trusted network perimeter before they can even attempt to authenticate to the database.

## How Checkov evaluates this
- ARM/Bicep: reads `properties/publicNetworkAccess` on `Microsoft.DBforPostgreSQL/servers` and expects the exact value `"Disabled"`. If the property/block is missing, the check's `missing_block_result` is FAILED — i.e., no explicit setting is treated as non-compliant.
- Terraform: reads `public_network_access_enabled` on `azurerm_postgresql_server` and expects `false`; a missing attribute also defaults to FAILED via `missing_block_result`.

## Non-compliant example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "example-psqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "GP_Gen5_2"
  version  = "11"

  administrator_login          = "psqladminun"
  administrator_login_password = var.psql_password

  ssl_enforcement_enabled       = true
  public_network_access_enabled = true
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "example-psqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "GP_Gen5_2"
  version  = "11"

  administrator_login          = "psqladminun"
  administrator_login_password = var.psql_password

  ssl_enforcement_enabled       = true
  public_network_access_enabled = false  # disable public endpoint
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess: "Disabled"` (ARM/Bicep) explicitly — do not rely on defaults, since a missing value is treated as non-compliant by this check.
2. Create a Private Endpoint (`azurerm_private_endpoint` with the `postgresqlServer` subresource) so trusted VNet-connected consumers retain access.
3. Migrate connection strings/DNS to resolve via the `privatelink.postgres.database.azure.com` private DNS zone.
4. Note `azurerm_postgresql_server` (single server) is deprecated in favor of `azurerm_postgresql_flexible_server`; on the flexible server the equivalent setting is under the `network` block (`public_network_access_enabled`).
5. Test all application/service connectivity from inside the VNet before fully cutting over, to avoid an outage.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/PostgreSQLServerPublicAccessDisabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerPublicAccessDisabled.py)
- [Azure docs: Private Link for Azure Database for PostgreSQL – Single Server](https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-data-access-security-private-link)
