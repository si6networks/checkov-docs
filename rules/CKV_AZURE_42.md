# CKV_AZURE_42: Ensure the key vault is recoverable

## Severity
**LOW** (score: 2.0/10)

Without soft-delete and purge protection, a Key Vault holding cryptographic keys and secrets can be permanently and irreversibly deleted by mistake or by a malicious actor with delete rights, destroying critical security material with no recovery path.

## Summary
This check verifies that an Azure Key Vault has both Soft Delete and Purge Protection enabled, so deleted vaults/secrets/keys/certificates can be recovered and cannot be permanently and immediately destroyed.

## Applicability
- **Terraform**: `azurerm_key_vault`
- **ARM templates**: `Microsoft.KeyVault/vaults`
- **Bicep**: `Microsoft.KeyVault/vaults`

## Why it matters
Without Soft Delete, deleting a Key Vault (or an item in it) is immediate and irreversible — a mistaken `terraform destroy`, a malicious insider, or an attacker with sufficient permissions could permanently wipe out encryption keys and secrets, causing irrecoverable data loss (e.g., data encrypted with a deleted key becomes permanently unreadable) or a total outage. Soft Delete alone still allows an authorized principal to *purge* (permanently delete) a soft-deleted vault/item before its retention period ends, which is exactly the loophole Purge Protection closes: once enabled, purge protection cannot be disabled, and items cannot be permanently deleted until the retention period naturally expires (default 90 days) even if someone tries. This combination is what actually makes deletion "safe" — soft delete alone is not sufficient protection against a determined attacker or a rushed `terraform destroy -auto-approve` in production.

## How Checkov evaluates this
- **ARM**: Reads `properties.enablePurgeProtection` and `properties.enableSoftDelete`. PASSES only if both are present and both equal (case-insensitively) `"true"`. Note this check is not applicable to the old `2015-06-01` API version, which didn't support `enablePurgeProtection`.
- **Terraform**: PASSES if `purge_protection_enabled == true` AND (`soft_delete_enabled` is either absent — meaning Azure's current default of enabled — or explicitly `true`). Any other combination FAILS.

## Non-compliant example
```hcl
resource "azurerm_key_vault" "example" {
  name                = "example-kv"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  purge_protection_enabled = false
}
```

## Remediated example
```hcl
resource "azurerm_key_vault" "example" {
  name                = "example-kv"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  purge_protection_enabled   = true
  soft_delete_retention_days = 90
}
```

## Remediation steps
1. Set `purge_protection_enabled = true` on the `azurerm_key_vault` resource (or `properties.enablePurgeProtection = true` in ARM/Bicep).
2. Confirm soft delete is enabled — it has been the mandatory default in Azure since 2020, but explicitly set `soft_delete_retention_days` (default 90, configurable 7–90) to control the recovery window.
3. **Caveat: purge protection cannot be disabled once turned on**, and enabling it may require the vault to be recreated depending on current state — plan for potential downtime/replacement in Terraform (`terraform plan` will indicate if a replace is required).
4. Ensure your IaC pipeline does not attempt `terraform destroy` on vaults with purge protection enabled without first accounting for the mandatory soft-delete retention period — the vault will linger in a soft-deleted state and block recreation with the same name until purged or the retention period lapses.
5. Grant appropriate RBAC/access policy permissions for recovering soft-deleted vaults/secrets to your operations team so accidental deletions can actually be reversed.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/KeyvaultRecoveryEnabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyvaultRecoveryEnabled.py)
- [Azure Key Vault soft-delete overview](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview)
