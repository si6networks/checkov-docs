# CKV_AZURE_129: Ensure that MariaDB server enables geo-redundant backups
## Severity
**LOW** (score: 2.0/10)

Missing geo-redundant backups is an availability/disaster-recovery gap affecting data durability after a regional outage, not a confidentiality or direct exploitation risk.

## Summary
This check verifies that an Azure Database for MariaDB server is configured with geo-redundant backup storage, so automated backups survive a regional outage or disaster affecting the primary Azure region.

## Applicability
- **IaC frameworks:** Terraform, ARM templates, Bicep
- **Resource types:**
  - Terraform: `azurerm_mariadb_server`
  - ARM: `Microsoft.DBforMariaDB/servers`

## Why it matters
Azure automatically takes backups of MariaDB databases, but by default those backups are stored redundantly only within the same region as the database. If an entire Azure region becomes unavailable — due to a natural disaster, major infrastructure failure, or regional outage — locally-redundant backups are unavailable right along with the primary database, leaving the organization with no way to restore service or data in another region. Geo-redundant backup storage replicates backups to a paired Azure region, so a regional disaster doesn't simultaneously destroy both the live database and its recovery point. This is a foundational business-continuity/disaster-recovery control: without it, an organization's recovery time objective (RTO) and recovery point objective (RPO) for a regional outage scenario are effectively undefined, since there is nothing to restore from outside the affected region.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects a single attribute:
- Terraform: `geo_redundant_backup_enabled`.
- ARM: `properties.storageProfile.geoRedundantBackup`.
- **PASS** if the Terraform attribute is truthy, or if the ARM property equals the literal string `"Enabled"`.
- **FAIL** if the attribute/property is absent, `false` (Terraform), or any value other than `"Enabled"` (ARM, e.g. `"Disabled"`).

## Non-compliant example
```hcl
resource "azurerm_mariadb_server" "example" {
  name                = "mariadb-example"
  location             = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadminun"
  administrator_login_password = var.admin_password
  sku_name                     = "GP_Gen5_2"
  version                      = "10.2"

  ssl_enforcement_enabled = true
  # geo_redundant_backup_enabled not set -> defaults to disabled
}
```

## Remediated example
```hcl
resource "azurerm_mariadb_server" "example" {
  name                = "mariadb-example"
  location             = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadminun"
  administrator_login_password = var.admin_password
  sku_name                     = "GP_Gen5_2"
  version                      = "10.2"

  ssl_enforcement_enabled       = true
  geo_redundant_backup_enabled = true  # backups replicated to the paired region
}
```

## Remediation steps
1. Set `geo_redundant_backup_enabled = true` on the `azurerm_mariadb_server` resource (Terraform), or `properties.storageProfile.geoRedundantBackup: "Enabled"` (ARM/Bicep).
2. Note that geo-redundant backup can typically only be set at server creation time — enabling it on an existing server usually requires provisioning a new server with the setting enabled and migrating data, so plan this into initial server design.
3. Verify your chosen SKU tier supports geo-redundant backup (this is generally a General Purpose/Memory Optimized tier feature, not available on Basic tier).
4. Be aware this roughly doubles backup storage costs since backups are now stored in two regions — factor this into cost planning.
5. Azure Database for MariaDB is on a retirement path in favor of other managed database options — confirm this service is still part of your long-term architecture before investing further here.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MariaDBGeoBackupEnabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/MariaDBGeoBackupEnabled.py)
- [Azure Database for MariaDB backup and restore documentation](https://learn.microsoft.com/en-us/azure/mariadb/concepts-backup)
