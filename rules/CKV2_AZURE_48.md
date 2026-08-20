# CKV2_AZURE_48: Ensure that Databricks Workspaces enables customer-managed key for root DBFS encryption

## Severity
**LOW** (score: 2.0/10)

Databricks DBFS root storage is still encrypted with a Microsoft-managed key by default, so the absence of a customer-managed key reduces control over key rotation/revocation for sensitive data rather than leaving the data unencrypted.

## Summary
This check ensures an Azure Databricks workspace on the Premium SKU is configured to encrypt its root DBFS (Databricks File System) storage using a customer-managed key (CMK) rather than relying solely on Microsoft-managed keys.

## Applicability
- **IaC frameworks:** Terraform (graph-based check), ARM/Bicep (Python resource check)
- **Resource types:** `Microsoft.Databricks/workspaces` (ARM/Bicep), `azurerm_databricks_workspace` + `azurerm_databricks_workspace_root_dbfs_customer_managed_key` (Terraform)

## Why it matters
The root DBFS store holds notebooks, libraries, job configurations, cluster logs, and often data extracted or cached during Databricks jobs — potentially including sensitive business or customer data. With Microsoft-managed keys, Microsoft controls the encryption keys and their lifecycle, and organizations have no ability to revoke access to the encrypted data independently of Microsoft, no auditable key-usage trail under their own control, and no way to meet compliance mandates (common in finance/healthcare) that require organizational control over key material and the ability to instantly "shred" data by revoking key access. Customer-managed keys stored in Azure Key Vault give the organization full control: they can rotate, disable, or delete the key to render the DBFS data permanently inaccessible, and they get an audit trail of every key operation via Key Vault logging.

## How Checkov evaluates this
**ARM (Python check, `DatabricksWorkspaceDBFSRootEncryptedWithCustomerManagedKey`):** Inspects `conf["properties"]["parameters"]`. FAILS if `prepareEncryption/value` is missing or not `"true"` (case-insensitive string comparison). Also FAILS if `encryption/value` is missing entirely, even if `prepareEncryption` is true. PASSES only when both `prepareEncryption` is true and an `encryption` settings block is present.

**Terraform (graph-based JSON policy):** PASSES under either branch:
1. The `azurerm_databricks_workspace`'s `sku` is **not** `"premium"` — CMK for root DBFS is a Premium-only feature, so non-Premium workspaces are exempted.
2. The `sku` **is** `"premium"`, **and** `customer_managed_key_enabled = true` is set on the workspace, **and** the workspace is connected to an `azurerm_databricks_workspace_root_dbfs_customer_managed_key` resource.

A Premium workspace that lacks `customer_managed_key_enabled = true` or has no connected root-DBFS CMK resource FAILS.

## Non-compliant example
```hcl
resource "azurerm_databricks_workspace" "example" {
  name                = "example-databricks"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "premium"
  # customer_managed_key_enabled not set; no CMK for root DBFS configured
}
```

## Remediated example
```hcl
resource "azurerm_databricks_workspace" "example" {
  name                          = "example-databricks"
  resource_group_name           = azurerm_resource_group.example.name
  location                      = azurerm_resource_group.example.location
  sku                           = "premium"
  customer_managed_key_enabled  = true    # required to allow CMK to be attached later
}

resource "azurerm_key_vault_key" "dbfs" {
  name         = "dbfs-cmk"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}

resource "azurerm_databricks_workspace_root_dbfs_customer_managed_key" "example" {
  workspace_id     = azurerm_databricks_workspace.example.id
  key_vault_key_id = azurerm_key_vault_key.dbfs.id
}
```

## Remediation steps
1. Ensure the Databricks workspace uses the `premium` SKU (CMK for root DBFS is unavailable on `standard`).
2. Set `customer_managed_key_enabled = true` on the `azurerm_databricks_workspace` resource — this must be enabled at workspace creation to allow attaching the key.
3. Create/reference an Azure Key Vault key, granting the Databricks workspace's managed identity `get`, `wrapKey`, and `unwrapKey` permissions on the vault.
4. Create an `azurerm_databricks_workspace_root_dbfs_customer_managed_key` resource linking the workspace to the Key Vault key.
5. Note: enabling CMK for root DBFS on an existing workspace may require workspace downtime or specific migration steps — consult Microsoft's Databricks CMK activation documentation before applying to production.
6. Set up Key Vault access policies/RBAC and monitoring so key deletion/rotation events are tracked and alertable.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/DatabricksWorkspaceDBFSRootEncryptedWithCustomerManagedKey.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/DatabricksWorkspaceDBFSRootEncryptedWithCustomerManagedKey.json)
- [Azure Databricks: Customer-managed keys for DBFS root documentation](https://learn.microsoft.com/en-us/azure/databricks/security/keys/customer-managed-key-dbfs)
