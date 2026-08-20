# CKV_AZURE_206: Ensure that Storage Accounts use replication

## Severity
**LOW** (score: 2.0/10)

Locally/zone-redundant-only replication is an availability and business-continuity gap (risk of data loss/unavailability in a regional disaster) rather than a confidentiality or access-control weakness.

## Summary
This check ensures an Azure Storage Account uses a geo-redundant replication SKU (GRS, RAGRS, GZRS, or RAGZRS) rather than a purely locally/zone-redundant option, so data survives a regional outage.

## Applicability
- **Frameworks:** Terraform, ARM templates, Bicep
- **Resource types:** `azurerm_storage_account` (Terraform), `Microsoft.Storage/storageAccounts` (ARM/Bicep)

## Why it matters
Storage accounts configured with only local redundancy (LRS) or zone redundancy (ZRS) replicate data within a single Azure region (across racks or availability zones respectively), but have no copy in a secondary geographic region. If that entire region experiences an outage — a natural disaster, a major power/networking failure, or a large-scale platform incident — data in an LRS/ZRS-only account becomes unavailable, and in true region-loss scenarios, potentially unrecoverable. Geo-redundant replication (GRS/RAGRS/GZRS/RAGZRS) asynchronously copies data to a paired secondary region hundreds of kilometers away, providing durability and business continuity guarantees against region-level disasters. This is a reliability/business-continuity control rather than a direct security control, but data unavailability and data loss are core components of the confidentiality-integrity-availability triad this check protects.

## How Checkov evaluates this
**Terraform** — `BaseResourceValueCheck`:
- **Inspected key:** `account_replication_type`
- **Accepted values:** `"GRS"`, `"RAGRS"`, `"GZRS"`, `"RAGZRS"` (any of these PASSES).
- FAILS if set to `"LRS"` or `"ZRS"`, or left at the provider default (`LRS`).

**ARM/Bicep** — `BaseResourceValueCheck`:
- **Inspected key:** `sku/name`
- **Accepted values:** `"Standard_GRS"`, `"Standard_RAGRS"`, `"Standard_GZRS"`, `"Standard_RAGZRS"`.
- FAILS if the SKU name is `Standard_LRS`, `Standard_ZRS`, `Premium_LRS`, or similar non-geo-redundant SKUs.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"   # no geo-redundancy
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"   # geo-redundant replication enabled
}
```

## Remediation steps
1. Change `account_replication_type` (Terraform) or `sku.name` (ARM/Bicep) to one of `GRS`, `RAGRS`, `GZRS`, or `RAGZRS` (or the `Standard_*` equivalents in ARM).
2. Choose `RAGRS`/`RAGZRS` if you need read access to the secondary region during a primary region outage; otherwise `GRS`/`GZRS` suffices for failover-only redundancy.
3. Be aware that changing replication type on an existing account can trigger a data resync and may briefly impact I/O performance; also note that converting from LRS to GRS is generally supported without downtime, but converting between ZRS and GRS/GZRS types can have restrictions depending on account kind — verify against current Azure documentation before applying to a production account.
4. Geo-redundant SKUs cost more than LRS — factor this into budget planning for accounts holding non-critical, easily reproducible data.
5. Consider Azure Storage's Customer-Managed Failover feature if RA-GRS/RA-GZRS is used, to formalize your disaster recovery runbook.

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountsUseReplication.py)
- [Checkov ARM check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/StorageAccountsUseReplication.py)
- [Azure Storage redundancy documentation](https://learn.microsoft.com/en-us/azure/storage/common/storage-redundancy)
