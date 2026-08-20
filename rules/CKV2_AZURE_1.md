# CKV2_AZURE_1: Ensure storage for critical data are encrypted with Customer Managed Key

## Severity
**HIGH** (score: 7.5/10)

Storage accounts are still encrypted at rest by default with Microsoft-managed keys, so lacking a customer-managed key mainly weakens key-rotation and access-revocation control rather than leaving data unencrypted.

## Summary
This check ensures an Azure Storage Account is configured to encrypt data at rest using a customer-managed key (CMK) stored in Azure Key Vault, rather than relying solely on Microsoft-managed keys.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `azurerm_storage_account`, connected via `azurerm_storage_account_customer_managed_key`, or configured directly through the `customer_managed_key` block's `key_vault_key_id` attribute.

## Why it matters
By default, Azure Storage Accounts encrypt data at rest with Microsoft-managed keys, which provide encryption but no customer control over key lifecycle: you cannot rotate on your own schedule, revoke access instantly, or satisfy compliance regimes (e.g. FedRAMP, PCI-DSS, certain financial/healthcare regulations) that mandate customer control of encryption keys. Using a customer-managed key stored in Key Vault means the organization controls key rotation, access policies, and can immediately revoke access to a compromised storage account by disabling the key — an important incident-response lever that Microsoft-managed keys don't provide. Without CMK, an organization has weaker technical enforcement of "who can decrypt this data" and cannot demonstrate independent key custody to auditors.

## How Checkov evaluates this
Graph check (`StorageCriticalDataEncryptedCMK.json`). PASS if **either**:
1. The `azurerm_storage_account` is connected to an `azurerm_storage_account_customer_managed_key` resource, **or**
2. The storage account has an inline `customer_managed_key.key_vault_key_id` attribute set directly.

FAIL if neither condition holds — i.e., the storage account has no customer-managed key configured by either mechanism, meaning it relies on Microsoft-managed keys only.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "data" {
  name                     = "criticaldatastorage"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # No customer_managed_key configured -> Microsoft-managed keys only
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "data" {
  name                     = "criticaldatastorage"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_key_vault_key" "storage_key" {
  name         = "storage-cmk"
  key_vault_id = azurerm_key_vault.kv.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}

resource "azurerm_storage_account_customer_managed_key" "data_cmk" {
  storage_account_id = azurerm_storage_account.data.id
  key_vault_id        = azurerm_key_vault.kv.id
  key_name            = azurerm_key_vault_key.storage_key.name
}
```

## Remediation steps
1. Enable a managed identity (`SystemAssigned` or `UserAssigned`) on the storage account so it can authenticate to Key Vault.
2. Create or reference an `azurerm_key_vault_key` in an Azure Key Vault with soft-delete and purge protection enabled (required for CMK on storage accounts).
3. Grant the storage account's managed identity `Get`, `WrapKey`, and `UnwrapKey` permissions on the Key Vault key (via Key Vault access policy or RBAC role `Key Vault Crypto Service Encryption User`).
4. Add an `azurerm_storage_account_customer_managed_key` resource linking the storage account to the Key Vault key, or set `customer_managed_key { key_vault_key_id = ... }` inline (requires provider support — check your `azurerm` provider version).
5. Converting an existing storage account from Microsoft-managed to customer-managed keys is an in-place update, but plan for the identity/Key Vault dependency chain to avoid apply-order errors (Key Vault access policy must exist before the CMK association can succeed).
6. Set up key rotation policies in Key Vault and monitor key expiration to avoid data-access outages if a key expires without rotation.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/StorageCriticalDataEncryptedCMK.json)
- [Azure: Customer-managed keys for Azure Storage encryption](https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview)
