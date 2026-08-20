# CKV_AZURE_76: Ensure that Azure Batch account uses key vault to encrypt data

## Severity
**LOW** (score: 2.0/10)

Without Key Vault-managed encryption, Batch account data relies on platform-managed keys only, reducing control over key rotation/revocation for potentially sensitive job and task data at rest.

## Summary
This check ensures an Azure Batch account is configured with a Key Vault reference so that data can be encrypted using customer-managed keys (CMK) instead of relying solely on Microsoft-managed keys.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_batch_account`
- **ARM/Bicep**: `Microsoft.Batch/batchAccounts`

## Why it matters
By default, Azure Batch account data (task metadata, certificates used for compute node configuration, etc.) is encrypted with Microsoft-managed keys, which Microsoft controls the lifecycle of. For organizations needing to enforce their own key rotation policy, revoke access instantly by disabling a key, or satisfy regulatory requirements (e.g. HIPAA, PCI-DSS) demanding customer control over encryption keys, a Key Vault-backed CMK configuration is required. Without it, the organization cannot independently revoke encryption access to Batch data, and key management is entirely outsourced to the platform.

## How Checkov evaluates this
`BaseResourceValueCheck` inspects `key_vault_reference/[0]/id` (Terraform) or `properties/keyVaultReference` (ARM) and expects `ANY_VALUE` — i.e. it passes as soon as any Key Vault reference/ID is configured, and fails if the `key_vault_reference` block (or `keyVaultReference` property) is absent.

## Non-compliant example
```hcl
resource "azurerm_batch_account" "example" {
  name                 = "examplebatchaccount"
  resource_group_name  = azurerm_resource_group.example.name
  location             = azurerm_resource_group.example.location
  pool_allocation_mode = "BatchService"
  storage_account_id   = azurerm_storage_account.example.id
  # no key_vault_reference -> encryption relies on Microsoft-managed keys only
}
```

## Remediated example
```hcl
resource "azurerm_batch_account" "example" {
  name                 = "examplebatchaccount"
  resource_group_name  = azurerm_resource_group.example.name
  location             = azurerm_resource_group.example.location
  pool_allocation_mode = "UserSubscription"
  storage_account_id   = azurerm_storage_account.example.id

  key_vault_reference {
    id  = azurerm_key_vault.example.id
    url = azurerm_key_vault.example.vault_uri
  }
}
```

## Remediation steps
1. Provision (or reuse) an Azure Key Vault with a key intended for Batch account encryption.
2. Add a `key_vault_reference` block to the `azurerm_batch_account` resource, referencing the Key Vault's `id` and `url`.
3. Note: `pool_allocation_mode` must be `UserSubscription` for CMK/Key Vault-backed configurations in Batch — `BatchService` mode does not support it, so this may require restructuring pool allocation and is often not a drop-in change.
4. Grant the Batch account's managed identity `get`/`unwrapKey`/`wrapKey` access to the Key Vault via an access policy or RBAC role.
5. This is typically a creation-time decision; changing `pool_allocation_mode` on an existing account requires recreating the Batch account.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureBatchAccountUsesKeyVaultEncryption.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureBatchAccountUsesKeyVaultEncryption.py
- Azure docs: https://learn.microsoft.com/en-us/azure/batch/batch-customer-managed-key
