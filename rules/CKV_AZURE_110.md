# CKV_AZURE_110: Ensure that key vault enables purge protection
## Severity
**LOW** (score: 2.0/10)

Without purge protection, an attacker or malicious insider who compromises sufficient privileges could permanently and irrecoverably delete Key Vault keys/secrets even after soft-delete, undermining recovery from a security incident.

## Summary
This check ensures that an Azure Key Vault has purge protection enabled, preventing keys, secrets, and certificates from being permanently and irreversibly deleted before their configured retention period expires.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_key_vault` (inspects `purge_protection_enabled`)
- **ARM/Bicep**: `Microsoft.KeyVault/vaults` (inspects `properties/enablePurgeProtection`)

## Why it matters
Key Vault's soft-delete feature retains deleted vaults/objects for a recovery window, but without purge protection, a user with sufficient permissions (or an attacker who compromises such an account) can immediately and permanently purge a soft-deleted vault or its keys, bypassing the recovery window entirely. This is a severe risk for ransomware-style attacks: an attacker who gains access could delete and then purge encryption keys used to protect other data, making that data permanently unrecoverable, or could destroy audit-relevant secrets to cover their tracks. Purge protection enforces a mandatory retention period (matching the soft-delete retention, minimum 7 days) during which even a Owner/Contributor-level identity cannot force-purge the vault — providing a hard backstop against accidental or malicious permanent data loss.

## How Checkov evaluates this
- **Terraform**: inspects `purge_protection_enabled` on `azurerm_key_vault`. This is a `BaseResourceValueCheck` with the default expected-value behavior (truthy expected) — the attribute must be `true` to **PASS**. If absent or `false`, it **FAILS** (the Terraform provider default for this attribute is `false`).
- **ARM**: inspects `properties/enablePurgeProtection` and expects `true`.

## Non-compliant example
```hcl
resource "azurerm_key_vault" "bad_example" {
  name                     = "bad-keyvault"
  location                 = azurerm_resource_group.example.location
  resource_group_name      = azurerm_resource_group.example.name
  tenant_id                = data.azurerm_client_config.current.tenant_id
  sku_name                 = "standard"

  purge_protection_enabled = false
}
```

## Remediated example
```hcl
resource "azurerm_key_vault" "good_example" {
  name                     = "good-keyvault"
  location                 = azurerm_resource_group.example.location
  resource_group_name      = azurerm_resource_group.example.name
  tenant_id                = data.azurerm_client_config.current.tenant_id
  sku_name                 = "standard"

  soft_delete_retention_days = 90
  # Fix: enable purge protection so deleted objects cannot be force-purged early
  purge_protection_enabled   = true
}
```

## Remediation steps
1. Set `purge_protection_enabled = true` (Terraform) or `properties.enablePurgeProtection = true` (ARM/Bicep) on the Key Vault resource.
2. Be aware this is a **one-way, irreversible setting** — once purge protection is enabled, it cannot be disabled for the life of the vault. Plan accordingly (e.g., don't enable it on ephemeral throwaway test vaults you intend to delete immediately).
3. Also configure an appropriate `soft_delete_retention_days` (7–90 days) so deleted-but-recoverable objects have a meaningful recovery window.
4. Update any automation that deletes and recreates vaults/keys with the same name to account for the retention period — a purge-protected, soft-deleted vault name remains reserved until the retention period elapses or is explicitly recovered.
5. Confirm your break-glass/recovery runbooks include steps to recover soft-deleted vaults/keys within the retention window.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/KeyVaultEnablesPurgeProtection.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyVaultEnablesPurgeProtection.py)
- [Azure docs: Azure Key Vault soft-delete overview](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview)
