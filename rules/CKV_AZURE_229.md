# CKV_AZURE_229: Ensure the Azure SQL Database Namespace is zone redundant

## Severity
**HIGH** (score: 7.5/10)

Missing zone redundancy for Azure SQL Database is an availability/resilience gap rather than a confidentiality or integrity risk, so a regional outage could cause downtime but does not directly expose data.

## Summary
This check ensures that an Azure SQL Database is configured for zone redundancy, so that the database's compute and storage are replicated across multiple Azure Availability Zones within the region.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_mssql_database` resources — inspects the `zone_redundant` attribute.
- **ARM/Bicep**: `Microsoft.Sql/servers/databases` resources — inspects `properties.zoneRedundant`.

## Why it matters
Azure Availability Zones are physically separate datacenters within a region, each with independent power, cooling, and networking. Without zone redundancy, an Azure SQL Database's compute and storage replicas live in a single zone. If that zone experiences an outage (power failure, network partition, or hardware fault affecting the facility), the database becomes unavailable until Azure fails it over or the zone recovers — causing an availability incident for any application depending on it.

Zone-redundant configuration also changes maintenance behavior: platform patches and updates can be rolled out zone-by-zone while other zones continue serving traffic, reducing planned-maintenance downtime windows. This is most relevant for production, customer-facing, or otherwise availability-sensitive databases; note that zone redundancy is only available on the vCore purchasing model's General Purpose, Premium, Business Critical, and Hyperscale tiers — not the DTU-based Basic/Standard tiers — and it can add latency-sensitive OLTP overhead, so it isn't universally required.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (a simple attribute-value check, not a graph check):
- **Terraform**: looks at the `zone_redundant` argument on `azurerm_mssql_database`. The check PASSES only if this is explicitly set to `true`; it FAILS if omitted or set to `false`.
- **ARM/Bicep**: looks at `properties.zoneRedundant` on `Microsoft.Sql/servers/databases`. Same pass/fail logic — must be present and truthy.

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.admin_password
}

resource "azurerm_mssql_database" "example" {
  name         = "example-db"
  server_id    = azurerm_mssql_server.example.id
  sku_name     = "GP_Gen5_2"
  # zone_redundant not set -> defaults to false, FAILS the check
}
```

## Remediated example
```hcl
resource "azurerm_mssql_database" "example" {
  name           = "example-db"
  server_id      = azurerm_mssql_server.example.id
  sku_name       = "GP_Gen5_2"
  zone_redundant = true   # <-- enables zone redundancy, PASSES the check
}
```

## Remediation steps
1. Confirm the database's SKU is on the vCore model in a tier that supports zone redundancy (General Purpose, Premium, Business Critical, or Hyperscale). Basic/Standard DTU tiers do not support this and cannot pass the check without a SKU change.
2. Set `zone_redundant = true` (Terraform) or `properties.zoneRedundant: true` (ARM/Bicep) on the database resource.
3. Verify the target Azure region supports Availability Zones — not all regions do.
4. Be aware that enabling zone redundancy on an existing database can trigger a resource modification/migration in Azure and may briefly affect availability during the change; plan a maintenance window.
5. For databases that are latency-sensitive OLTP workloads or low-maturity/dev environments where the added complexity isn't warranted, consider whether a documented risk-acceptance exception is more appropriate than blanket enablement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLDatabaseZoneRedundant.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SQLDatabaseZoneRedundant.py
- Azure docs: https://learn.microsoft.com/en-us/azure/azure-sql/database/high-availability-sla
