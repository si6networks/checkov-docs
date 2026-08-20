# CKV_AZURE_113: Ensure that SQL server disables public network access
## Severity
**HIGH** (score: 7.5/10)

Leaving public network access enabled on a SQL Server exposes a sensitive database service to network-level reconnaissance and attack attempts beyond the trusted virtual network boundary.

## Summary
This check ensures that an Azure SQL logical server disables public network access, so the server can only be reached through private connectivity (Private Link/VNet) rather than the public internet.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_mssql_server` (inspects `public_network_access_enabled`)
- **ARM/Bicep**: `Microsoft.Sql/servers` (inspects `properties/publicNetworkAccess`)

## Why it matters
Even with firewall rules and IP allow-listing in place (see CKV_AZURE_11), leaving public network access enabled means the SQL server's endpoint is still discoverable and reachable over the internet, subject only to whatever firewall rules happen to be configured — a single misconfigured or overly-broad firewall rule turns into full internet exposure. Disabling public network access entirely removes the public data-plane endpoint, forcing all connectivity through Private Link/VNet integration. This is a stronger control than firewall rules alone: it eliminates the risk of a firewall-rule misconfiguration exposing the database, and ensures that database credentials leaked or brute-forced by an external attacker are useless without also having network-level access to the private endpoint.

## How Checkov evaluates this
Both implementations use `missing_block_result=CheckResult.FAILED` — if the field is not set at all, the check treats this as a failure rather than assuming a safe default, since the Azure/provider default for this setting is `Enabled`/`true` (public access on).
- **Terraform**: inspects `public_network_access_enabled` on `azurerm_mssql_server`; expects `false`.
- **ARM**: inspects `properties/publicNetworkAccess`; expects the string `"Disabled"`.

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "bad_example" {
  name                         = "bad-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.admin_password

  public_network_access_enabled = true
}
```

## Remediated example
```hcl
resource "azurerm_mssql_server" "good_example" {
  name                         = "good-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.admin_password

  # Fix: disable public network access; require private endpoint connectivity
  public_network_access_enabled = false
}

resource "azurerm_private_endpoint" "sql_pe" {
  name                = "sql-server-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "sql-privatelink"
    private_connection_resource_id = azurerm_mssql_server.good_example.id
    subresource_names              = ["sqlServer"]
    is_manual_connection           = false
  }
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess = "Disabled"` (ARM/Bicep) on the SQL server resource.
2. Provision a Private Endpoint for the `sqlServer` sub-resource so application/service traffic inside the VNet can still connect.
3. Migrate application connection strings to resolve through the private endpoint's private DNS zone (`privatelink.database.windows.net`).
4. Remove now-redundant public firewall rules once private connectivity is confirmed working, since they no longer provide any access path.
5. Test thoroughly before disabling in production — any client (including admin tools like SSMS or Azure Data Studio) connecting from outside the VNet will lose access unless routed through a VPN/ExpressRoute/jump host.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SQLServerHasPublicAccessDisabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerPublicAccessDisabled.py)
- [Azure docs: Azure SQL Database and Private Link](https://learn.microsoft.com/en-us/azure/azure-sql/database/private-endpoint-overview)
