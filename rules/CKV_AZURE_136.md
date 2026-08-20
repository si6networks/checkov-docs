# CKV_AZURE_136: Ensure that PostgreSQL Flexible server enables geo-redundant backups
## Severity
**LOW** (score: 2.0/10)

Missing geo-redundant backups for PostgreSQL Flexible Server is a data-durability/availability gap (risk of data loss on regional outage) rather than a direct confidentiality or access-control weakness.

## Summary
This check ensures an Azure Database for PostgreSQL Flexible Server has geo-redundant backups enabled, so backup data is replicated to a paired Azure region rather than kept only in the primary region.

## Applicability
- **Terraform**: `azurerm_postgresql_flexible_server` resource, attribute `geo_redundant_backup_enabled`.

## Why it matters
By default, PostgreSQL Flexible Server backups are stored locally-redundant within the primary region. If that entire Azure region suffers an outage or disaster (natural disaster, large-scale infrastructure failure), both the live database and its locally-redundant backups can become unavailable simultaneously, making point-in-time or full restore impossible until the region recovers — and in a worst case, backup data could be permanently lost. Geo-redundant backup storage replicates backups to the paired region, so a region-wide failure still leaves a restorable copy elsewhere, materially improving disaster-recovery posture and business continuity for a database tier that often holds business-critical relational data.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `geo_redundant_backup_enabled` attribute, expecting it to be truthy (enabled) to PASS. There is one special-cased exception in the Python source: if `create_mode` is set to `"Replica"`, the check unconditionally PASSES regardless of the `geo_redundant_backup_enabled` value — because read replicas cannot have their own independent geo-redundant backup configuration (backup behavior is inherited from/tied to the primary server), so enforcing the setting on a replica would be meaningless.

## Non-compliant example
```hcl
resource "azurerm_postgresql_flexible_server" "example" {
  name                   = "example-psqlflexibleserver"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  version                = "16"
  administrator_login    = "psqladmin"
  administrator_password = var.admin_password
  storage_mb             = 32768
  sku_name               = "GP_Standard_D2s_v3"
  # geo_redundant_backup_enabled left at default (false) -- FAILS
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_flexible_server" "example" {
  name                         = "example-psqlflexibleserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "16"
  administrator_login          = "psqladmin"
  administrator_password       = var.admin_password
  storage_mb                   = 32768
  sku_name                     = "GP_Standard_D2s_v3"
  geo_redundant_backup_enabled = true  # replicates backups to the paired region
}
```

## Remediation steps
1. Set `geo_redundant_backup_enabled = true` on `azurerm_postgresql_flexible_server` resources holding production or business-critical data.
2. Note this attribute can only be set at server creation time in Azure — changing it on an existing server typically requires recreating the server (Terraform will show a forced replacement), so plan for a migration window / restore-based cutover rather than expecting an in-place update.
3. Skip this setting only for genuine read replicas (`create_mode = "Replica"`), which the check already exempts, since replicas don't independently control geo-redundant backup.
4. Confirm your target region has a paired region supporting geo-redundant storage, and be aware of the additional storage cost geo-redundant backups incur.
5. Combine with an appropriate `backup_retention_days` setting to meet your recovery point objective (RPO).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLFlexiServerGeoBackupEnabled.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-backup-restore
