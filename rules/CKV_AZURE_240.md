# CKV_AZURE_240: Ensure Azure Synapse Workspace is encrypted with a CMK

## Severity
**LOW** (score: 2.0/10)

Relying on Microsoft-managed keys instead of a customer-managed key for Synapse Workspace encryption reduces the tenant's control over key rotation/revocation for data at rest, a moderate compliance and defense-in-depth gap rather than a direct exposure.

## Summary
This check ensures an Azure Synapse Analytics workspace is encrypted using a customer-managed key (CMK) stored in Azure Key Vault, rather than relying solely on Microsoft-managed keys.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_synapse_workspace` resources — inspects `customer_managed_key[0].key_name` (any non-empty value accepted).
- **ARM/Bicep**: `Microsoft.Synapse/workspaces` — inspects `properties.encryption` for the presence of a `cmk` key.

## Why it matters
By default, Synapse workspace data at rest is encrypted with Microsoft-managed keys, which Microsoft fully controls the lifecycle of — the customer has no ability to revoke, rotate on their own schedule, or audit key usage independently. For organizations handling regulated or highly sensitive analytical data (financial records, health data, PII), many compliance regimes (HIPAA, PCI-DSS, various data-sovereignty regulations) require the ability to control and revoke the encryption key independently of the cloud provider — for example, to cryptographically "shred" data by revoking Key Vault access to the key, or to demonstrate the organization retains ultimate control over data confidentiality. Customer-managed keys, stored in an Azure Key Vault the customer controls, give the workspace owner the ability to rotate keys on their own schedule, revoke access instantly (rendering the underlying data unreadable), and produce a Key Vault audit log of every key-access event tied to the workspace — none of which is possible with Microsoft-managed keys.

## How Checkov evaluates this
- **Terraform**: `BaseResourceValueCheck` using `ANY_VALUE` on `customer_managed_key[0].key_name`. PASSES if any key name is configured in a `customer_managed_key` block; FAILS if the block/key is absent.
- **ARM**: `BaseResourceCheck` reading `properties.encryption`. PASSES if the `"cmk"` key exists anywhere within that encryption object; FAILS otherwise.

## Non-compliant example
```hcl
resource "azurerm_synapse_workspace" "example" {
  name                                 = "example-synapse"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "sqladminuser"

  identity {
    type = "SystemAssigned"
  }
  # no customer_managed_key block -> relies on Microsoft-managed key, FAILS
}
```

## Remediated example
```hcl
resource "azurerm_synapse_workspace" "example" {
  name                                 = "example-synapse"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "sqladminuser"

  identity {
    type = "SystemAssigned"
  }

  customer_managed_key {                                    # <-- CMK configured, PASSES
    key_versionless_id = azurerm_key_vault_key.example.versionless_id
    key_name           = "synapse-cmk"
  }
}

resource "azurerm_key_vault_key" "example" {
  name         = "synapse-cmk"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "unwrapKey", "wrapKey"]
}
```

## Remediation steps
1. Create (or reuse) an Azure Key Vault key dedicated to Synapse workspace encryption.
2. Grant the Synapse workspace's managed identity (or the deploying principal, per Azure's workspace-creation-key rules) the necessary Key Vault permissions (`Get`, `WrapKey`, `UnwrapKey`) via access policy or RBAC.
3. Add a `customer_managed_key` block to the `azurerm_synapse_workspace` resource referencing the key.
4. Note: Synapse workspace CMK encryption is generally configured at workspace creation time; migrating an existing workspace from Microsoft-managed to customer-managed keys may not be supported in-place and could require workspace recreation — verify current Azure support before planning.
5. Ensure the Key Vault has soft-delete and purge protection enabled, and back up/escrow the key material appropriately — losing the CMK renders all encrypted Synapse data permanently unreadable.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SynapseWorkspaceCMKEncryption.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SynapseWorkspaceCMKEncryption.py
- Azure docs: https://learn.microsoft.com/en-us/azure/synapse-analytics/security/workspaces-encryption
