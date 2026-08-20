# CKV_AZURE_105: Ensure that Data Lake Store accounts enables encryption
## Severity
**MEDIUM** (score: 5.0/10)

Disabling encryption on a Data Lake Store account leaves data at rest unprotected, exposing potentially sensitive analytics data to anyone who gains access to the underlying storage.

## Summary
This check ensures that an Azure Data Lake Store (Gen1) account has encryption of data at rest enabled.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_data_lake_store` (inspects `encryption_state`)
- **ARM/Bicep**: `Microsoft.DataLakeStore/accounts` (inspects `properties/encryptionState`)

## Why it matters
Data Lake Store is typically used to hold large volumes of raw and processed analytics data, which may include PII, financial data, or other sensitive information. Without encryption at rest, data written to the underlying storage is stored in plaintext at the disk/media level; if physical media, storage snapshots, or improperly-decommissioned hardware were ever compromised, the data would be directly readable. Enabling encryption (Azure-managed or customer-managed keys) ensures data is unreadable outside of the authorized service context, satisfying baseline data-at-rest protection requirements found in virtually every compliance framework (PCI-DSS, HIPAA, ISO 27001, SOC 2).

## How Checkov evaluates this
This is a `BaseResourceValueCheck` with `missing_block_result=CheckResult.PASSED` — meaning if the encryption attribute is entirely absent, Checkov treats it as compliant (since Data Lake Store enables encryption by default at creation and the field may simply not be set explicitly in some configurations).
- **Terraform**: inspects `encryption_state`; expects the value `"Enabled"`. If explicitly set to anything else (e.g., `"Disabled"`), the check **FAILS**.
- **ARM**: inspects `properties/encryptionState`; same expected value `"Enabled"`.

## Non-compliant example
```hcl
resource "azurerm_data_lake_store" "bad_example" {
  name                = "baddatalakestore"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  encryption_state = "Disabled"
}
```

## Remediated example
```hcl
resource "azurerm_data_lake_store" "good_example" {
  name                = "gooddatalakestore"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  # Fix: explicitly enable encryption at rest
  encryption_state = "Enabled"
  encryption_type  = "ServiceManaged"
}
```

## Remediation steps
1. Set `encryption_state = "Enabled"` (Terraform) or `properties.encryptionState = "Enabled"` (ARM/Bicep).
2. Choose `encryption_type` — `"ServiceManaged"` (Microsoft-managed keys) is the simplest option; customer-managed keys via Key Vault are also supported for stricter key-control requirements.
3. Note: the encryption state can only be set at account **creation time** for Data Lake Store Gen1 — it cannot be toggled on an existing account. Enabling it requires provisioning a new account and migrating data via `distcp`/ADLCopy or similar.
4. Consider migrating to Azure Data Lake Storage Gen2 (built on Blob Storage) for new deployments, since Gen1 is in maintenance/retirement mode; Gen2 storage accounts enable encryption by default and cannot be disabled.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/DataLakeStoreEncryption.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataLakeStoreEncryption.py)
- [Azure docs: Encryption of data in Azure Data Lake Store](https://learn.microsoft.com/en-us/azure/data-lake-store/data-lake-store-encryption)
