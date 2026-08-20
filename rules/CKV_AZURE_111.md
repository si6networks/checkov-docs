# CKV_AZURE_111: Ensure that key vault enables soft delete
## Severity
**LOW** (score: 2.0/10)

Without soft delete, accidental or malicious deletion of Key Vault objects is immediate and unrecoverable, creating an availability and incident-recovery gap for stored secrets and keys.

## Summary
This check ensures that an Azure Key Vault has soft delete enabled, so keys, secrets, and certificates (and the vault itself) can be recovered for a retention period after deletion rather than being removed immediately and permanently.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_key_vault` (inspects `soft_delete_enabled`)
- **ARM/Bicep**: `Microsoft.KeyVault/vaults` (inspects `properties/enableSoftDelete`)

## Why it matters
Without soft delete, deleting a Key Vault object (or the vault itself) is immediate and permanent — there is no recovery path for accidental deletion, a misconfigured Terraform `destroy`, a bad script, or a malicious/compromised actor deliberately destroying cryptographic material to cause data loss or cover their tracks. Since Key Vault often stores encryption keys that protect other data (databases, storage accounts, disks), permanent loss of a key can render dependent data permanently unrecoverable — a severe availability and business-continuity risk. Soft delete provides a mandatory recovery window (default 90 days) during which deleted objects can be restored, protecting against both accidental and malicious permanent loss.

## How Checkov evaluates this
Both implementations use `missing_block_result=CheckResult.PASSED`, reflecting that as of API version 2020+ Azure enables soft delete by default for new Key Vaults and this behavior became mandatory (all new vaults are created with soft delete on).
- **Terraform**: inspects `soft_delete_enabled` on `azurerm_key_vault`. If the attribute is present and explicitly `false`, the check **FAILS**. If absent, it is treated as **PASSED** (relying on the platform default).
- **ARM**: inspects `properties/enableSoftDelete`. Same logic — explicitly `false` **FAILS**; absent **PASSES**.

## Non-compliant example
```hcl
resource "azurerm_key_vault" "bad_example" {
  name                = "bad-keyvault"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  soft_delete_enabled = false
}
```

## Remediated example
```hcl
resource "azurerm_key_vault" "good_example" {
  name                       = "good-keyvault"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"

  # Fix: enable soft delete with an explicit retention period
  soft_delete_enabled        = true
  soft_delete_retention_days = 90
}
```

## Remediation steps
1. Remove any explicit `soft_delete_enabled = false` / `properties.enableSoftDelete = false` setting — soft delete is enabled by default on modern API versions and, for current `azurerm` provider versions, is generally non-configurable (always on) for new vaults.
2. Explicitly set `soft_delete_retention_days` to a value appropriate for your recovery requirements (7–90 days).
3. Note: soft delete cannot be disabled once enabled on a vault created with modern API versions — this is expected and desired behavior, not a limitation to work around.
4. Pair this with `purge_protection_enabled = true` (CKV_AZURE_110) for the strongest protection against permanent, unrecoverable deletion.
5. If using an older `azurerm` provider version where `soft_delete_enabled` still accepts `false`, upgrade the provider — recent versions of Azure Key Vault no longer support creating vaults without soft delete.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/KeyVaultEnablesSoftDelete.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyVaultEnablesSoftDelete.py)
- [Azure docs: Azure Key Vault soft-delete overview](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview)
