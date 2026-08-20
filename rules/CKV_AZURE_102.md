# CKV_AZURE_102: Ensure that PostgreSQL server enables geo-redundant backups
## Severity
**LOW** (score: 2.0/10)

Missing geo-redundant backups on a PostgreSQL server is primarily an availability/disaster-recovery gap rather than a direct confidentiality or integrity exposure.

## Summary
This check ensures that an Azure Database for PostgreSQL (single server) instance is configured to store its automated backups in a geo-redundant storage account rather than only locally-redundant storage.

## Applicability
- **Terraform**: `azurerm_postgresql_server` (inspects `geo_redundant_backup_enabled`)
- **ARM/Bicep**: `Microsoft.DBforPostgreSQL/servers` (inspects `properties/storageProfile/geoRedundantBackup`)

## Why it matters
Automated backups are the primary recovery mechanism when a database is corrupted, an operator makes a destructive mistake, or ransomware/an attacker deletes data. If backups are stored only in the same Azure region as the primary database (locally-redundant), a region-wide outage or disaster affecting that region can destroy both the live database and its backups simultaneously, leaving no path to recovery. Geo-redundant backup storage replicates backups to a paired secondary region, so recovery remains possible even if the primary region is completely unavailable. This directly affects business continuity and disaster recovery (BCDR) posture and is often a specific requirement in SOC 2 / ISO 27001 continuity controls.

## How Checkov evaluates this
- **Terraform**: inspects the `geo_redundant_backup_enabled` attribute on `azurerm_postgresql_server`. This is a `BaseResourceValueCheck` with no explicit expected value override, so it uses the check's default expected-value comparison (truthy) — the attribute must be set to `true` to **PASS**; if absent or `false`, it **FAILS**.
- **ARM**: inspects `properties/storageProfile/geoRedundantBackup` and expects the literal string `"Enabled"`. Any other value (including the default, `"Disabled"`) **FAILS**.

## Non-compliant example
```hcl
resource "azurerm_postgresql_server" "bad_example" {
  name                = "bad-postgres"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "GP_Gen5_4"

  storage_mb                   = 640000
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false

  administrator_login          = "psqladmin"
  administrator_login_password = var.admin_password
  version                      = "11"
  ssl_enforcement_enabled      = true
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_server" "good_example" {
  name                = "good-postgres"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "GP_Gen5_4"

  storage_mb             = 640000
  backup_retention_days  = 7
  # Fix: enable geo-redundant backup storage
  geo_redundant_backup_enabled = true

  administrator_login          = "psqladmin"
  administrator_login_password = var.admin_password
  version                      = "11"
  ssl_enforcement_enabled      = true
}
```

## Remediation steps
1. Set `geo_redundant_backup_enabled = true` (Terraform) or `properties.storageProfile.geoRedundantBackup = "Enabled"` (ARM/Bicep).
2. Note: geo-redundant backup can only be configured at server **creation time** — it cannot be toggled on for an existing PostgreSQL single server. Enabling this on an existing instance requires provisioning a new server with the setting enabled and migrating data (e.g., via `pg_dump`/`pg_restore` or point-in-time restore into a new geo-redundant-enabled server).
3. Confirm the SKU tier supports geo-redundant backup (General Purpose and Memory Optimized tiers support it; Basic tier does not).
4. Be aware this increases storage cost, since backups are replicated to the paired region.
5. Consider that Azure Database for PostgreSQL single server is on a deprecation path in favor of Flexible Server — for new deployments, use `azurerm_postgresql_flexible_server` with appropriate geo-redundant backup configuration instead.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/PostgressSQLGeoBackupEnabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgressSQLGeoBackupEnabled.py)
- [Azure docs: Backup and restore in Azure Database for PostgreSQL](https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-backup)
