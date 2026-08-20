# CKV_AZURE_100: Ensure that Cosmos DB accounts have customer-managed keys to encrypt data at rest
## Severity
**LOW** (score: 2.0/10)

Cosmos DB data is encrypted at rest by default with Microsoft-managed keys, so lacking a customer-managed key mainly weakens key ownership, rotation, and revocation control rather than leaving data unencrypted.

## Summary
This check ensures that Azure Cosmos DB accounts are configured to use a customer-managed key (CMK), stored in Azure Key Vault, to encrypt data at rest rather than relying solely on Microsoft-managed keys.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_cosmosdb_account` (inspects `key_vault_key_id`)
- **ARM/Bicep**: `Microsoft.DocumentDb/databaseAccounts` (inspects `properties/keyVaultKeyUri`)

## Why it matters
By default, Cosmos DB encrypts all data at rest using Microsoft-managed keys, which is good baseline hygiene but gives the account owner no direct control over key rotation, revocation, or access auditing. Using a customer-managed key stored in Key Vault means the organization controls the encryption key lifecycle independently of the data plane: keys can be rotated on a schedule, access to the key can be scoped and audited via Key Vault access policies/RBAC, and — critically — the key can be revoked to render the data cryptographically inaccessible (e.g., during an incident, offboarding, or regulatory deletion request) without needing to delete the underlying data itself. Many compliance frameworks (FedRAMP, HIPAA, PCI-DSS, and various sovereign/data-residency regimes) either require or strongly prefer CMK for regulated data, since Microsoft-managed keys do not provide an independent customer-controlled audit trail or "right to be forgotten via key destruction."

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using Checkov's `ANY_VALUE` sentinel:
- **Terraform**: looks at the `key_vault_key_id` attribute on `azurerm_cosmosdb_account`. The check **PASSES** if this attribute is set to any non-empty value, and **FAILS** if it is absent/unset.
- **ARM**: looks at `properties/keyVaultKeyUri`. Same logic — any non-empty value **PASSES**; absence **FAILS**.

The check does not validate that the referenced key exists, is enabled, or has proper access policies — only that a CMK reference is configured.

## Non-compliant example
```hcl
resource "azurerm_cosmosdb_account" "bad_example" {
  name                = "bad-cosmosdb"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.example.location
    failover_priority = 0
  }

  # No key_vault_key_id set -> Microsoft-managed key only
}
```

## Remediated example
```hcl
resource "azurerm_key_vault_key" "cosmos_cmk" {
  name         = "cosmos-cmk"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}

resource "azurerm_cosmosdb_account" "good_example" {
  name                = "good-cosmosdb"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.example.location
    failover_priority = 0
  }

  # Fix: reference a customer-managed key in Key Vault
  key_vault_key_id = azurerm_key_vault_key.cosmos_cmk.id
}
```

## Remediation steps
1. Create (or identify) an Azure Key Vault with soft-delete and purge protection enabled (required for CMK use with Cosmos DB).
2. Create a key in that vault (`azurerm_key_vault_key`) dedicated to Cosmos DB encryption.
3. Grant the Cosmos DB account's managed identity `wrapKey`/`unwrapKey`/`get` permissions on the key via a Key Vault access policy or RBAC role assignment.
4. Set `key_vault_key_id` (Terraform) / `properties.keyVaultKeyUri` (ARM/Bicep) on the Cosmos DB account to the key's versionless or versioned URI.
5. Note: CMK can only be configured at account creation time for most Cosmos DB accounts — switching an existing account from service-managed to customer-managed keys typically requires creating a new account and migrating data.
6. Establish a key-rotation policy and monitor Key Vault access logs for anomalous key usage.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/CosmosDBHaveCMK.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBHaveCMK.py)
- [Azure docs: Configure customer-managed keys for Azure Cosmos DB](https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-setup-cmk)
