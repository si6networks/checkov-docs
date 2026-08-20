# CKV_AZURE_94: Ensure that My SQL server enables geo-redundant backups
## Severity
**LOW** (score: 2.0/10)

Disabling geo-redundant backups on MySQL is primarily an availability/disaster-recovery gap, raising the risk of data loss during a regional outage rather than a confidentiality or access-control weakness.

## Summary
This check verifies that an Azure Database for MySQL server (single server or flexible server) has geo-redundant backups enabled, so backups are replicated to a paired Azure region.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_mysql_server`, `azurerm_mysql_flexible_server` (inspects `geo_redundant_backup_enabled`)
- **ARM templates**: `Microsoft.DBforMySQL/flexibleServers` (inspects `properties.Backup.geoRedundantBackup`)
- **Bicep**: resources compiling to the above ARM type

## Why it matters
Without geo-redundant backups, all automated backups for a MySQL server are stored only within the same Azure region as the primary database. This creates a single point of failure for disaster recovery:
- A regional outage, natural disaster, or large-scale Azure incident affecting the primary region would make both the live database **and** its backups unavailable simultaneously, leaving no recovery path until the region is restored.
- Organizations with Recovery Point Objective (RPO)/Recovery Time Objective (RTO) commitments or regulatory continuity requirements cannot meet cross-region disaster recovery obligations with locally-stored-only backups.
- It removes an inexpensive, low-effort layer of protection against a low-probability but high-impact failure mode (full-region loss).

Enabling geo-redundant backups ensures that even if the primary region becomes completely unavailable, the organization can restore the database from backups replicated in the paired region.

## How Checkov evaluates this
Uses `BaseResourceValueCheck` with no explicit expected value override, which means it defaults to checking for a "truthy"/enabled state:
- **Terraform**: Inspects `geo_redundant_backup_enabled`. The check expects this to be `true`/enabled; a `false` value or an unset attribute (which defaults to `Disabled` in the Azure API) fails.
- **ARM**: Inspects `properties.Backup.geoRedundantBackup`. Expects it to be enabled (`"Enabled"`); missing or `"Disabled"` fails.

## Non-compliant example
```hcl
resource "azurerm_mysql_flexible_server" "example" {
  name                   = "example-mysqlfs"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  administrator_login    = "mysqladmin"
  administrator_password = var.mysql_admin_password
  sku_name               = "GP_Standard_D2ds_v4"

  backup_retention_days        = 7
  geo_redundant_backup_enabled = false   # <-- backups only in the primary region
}
```

## Remediated example
```hcl
resource "azurerm_mysql_flexible_server" "example" {
  name                   = "example-mysqlfs"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  administrator_login    = "mysqladmin"
  administrator_password = var.mysql_admin_password
  sku_name               = "GP_Standard_D2ds_v4"

  backup_retention_days        = 7
  geo_redundant_backup_enabled = true   # <-- backups replicated to the paired region
}
```

## Remediation steps
1. Set `geo_redundant_backup_enabled = true` on the `azurerm_mysql_server`/`azurerm_mysql_flexible_server` resource (or `properties.Backup.geoRedundantBackup = "Enabled"` in ARM/Bicep).
2. Be aware this setting can typically only be configured at **server creation time** — enabling it on an existing server may require creating a new server and migrating data, so plan accordingly.
3. Confirm your SKU tier supports geo-redundant backup (available on General Purpose and Memory Optimized tiers; not always available on Burstable).
4. Factor in the additional storage cost, since geo-redundant backup storage is billed at a higher rate than locally-redundant backup storage.
5. Document and test the cross-region restore procedure as part of your disaster-recovery runbook.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLGeoBackupEnabled.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/MySQLGeoBackupEnabled.py
