# CKV_AZURE_43: Ensure Storage Accounts adhere to the naming rules

## Severity
**LOW** (score: 2.0/10)

Storage account naming convention violations are a hygiene/operational concern with no direct bearing on confidentiality, integrity, or availability of the account's data.

## Summary
This check verifies that an Azure Storage Account's name conforms to Azure's naming constraints: 3–24 characters, lowercase letters and digits only.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_storage_account`
- **ARM templates**: `Microsoft.Storage/storageAccounts`
- **Bicep**: `Microsoft.Storage/storageAccounts`

## Why it matters
This is primarily a reliability/convention check rather than a direct security control, but it prevents deployment-time failures and downstream automation breakage. Azure enforces this naming rule at the platform level (storage account names must be globally unique, 3–24 characters, lowercase alphanumeric only) — the check exists so IaC authors catch invalid names during a `checkov` scan/PR review instead of discovering the failure mid-deployment. Consistent naming conventions also matter operationally: scripts, monitoring queries, and access policies that parse or pattern-match storage account names (e.g., to apply tagging, cost allocation, or automated firewall rules) can break silently if names deviate from expected patterns, and inconsistent casing/characters make audit log correlation harder across a large estate.

## How Checkov evaluates this
- **Both ARM and Terraform**: Applies the regex `^[a-z0-9]{3,24}$` against the `name` attribute. PASSES if the name matches (lowercase letters/digits only, 3–24 characters long).
- **Special-cased exception**: If the name string contains a reference to a value that can't be statically evaluated at scan time — e.g., `local.`, `module.`, `var.`, `random_string.`, `random_id.`, `random_integer.`, `random_pet.`, `azurecaf_name`, `each.` (and, in the ARM check only, `substring`) — the check returns `UNKNOWN` rather than FAILED, since Checkov cannot determine the final rendered name statically.
- If `name` is missing entirely, or is present but fails the regex (and isn't one of the variable-reference exceptions), the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "Example-Storage-Account!"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct01"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
```

## Remediation steps
1. Rename the storage account to use only lowercase letters and digits (no hyphens, underscores, uppercase letters, or other symbols).
2. Ensure the name is between 3 and 24 characters long.
3. If you need a dynamic/generated name (e.g., for uniqueness across environments), use a naming module or the `random_string`/`random_id` resources, or the `azurecaf_name` provider, which are explicitly recognized by this check as "cannot statically evaluate" and won't be flagged as failing — but still ensure your generation logic itself respects the 3–24 character lowercase-alphanumeric constraint, since Checkov can't verify that for you.
4. Note: changing a storage account's `name` in Terraform forces resource replacement (new account, new endpoint, potential data migration) — this is not an in-place rename.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/StorageAccountName.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountName.py)
- [Azure Storage account naming rules](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview#storage-account-name)
