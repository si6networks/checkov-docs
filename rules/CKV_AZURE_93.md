# CKV_AZURE_93: Ensure that managed disks use a specific set of disk encryption sets for the customer-managed key encryption
## Severity
**LOW** (score: 2.0/10)

Azure managed disks are encrypted by default with platform-managed keys, so omitting a customer-managed disk encryption set weakens key-management control and separation of duties rather than leaving the data actually unencrypted.

## Summary
This check verifies that an Azure managed disk is configured to use a specific Disk Encryption Set (customer-managed key encryption) rather than relying only on Azure's default platform-managed key encryption.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_managed_disk` (inspects `disk_encryption_set_id`)
- **ARM templates**: `Microsoft.Compute/disks` (inspects `properties.encryption.diskEncryptionSetId`)
- **Bicep**: resources compiling to `Microsoft.Compute/disks`

## Why it matters
By default, Azure managed disks are encrypted at rest with platform-managed keys — Microsoft controls the encryption keys entirely, and the customer has no ability to rotate, revoke, or audit key usage. For workloads subject to regulatory or contractual requirements (e.g. data residency, "right to be forgotten" via key destruction, or compliance frameworks requiring customer key ownership), this is insufficient because:
- The organization cannot revoke access to the data by rotating/destroying a key it does not control, meaning there is no cryptographic "kill switch" independent of Azure.
- There is no way to enforce organization-specific key rotation policies or centralized key auditing (e.g. via Azure Key Vault access logs) for disk-level encryption.
- Compliance regimes that mandate customer-managed encryption keys (CMK) for data at rest cannot be satisfied with platform-managed keys alone.

Using a Disk Encryption Set backed by a customer's own Azure Key Vault key ensures the organization retains cryptographic control over disk data, with the ability to rotate or revoke keys and audit all key-access events independently of Microsoft.

## How Checkov evaluates this
Uses `BaseResourceValueCheck` with `ANY_VALUE` as the expected value — meaning the check simply verifies that the `disk_encryption_set_id` (Terraform) / `properties.encryption.diskEncryptionSetId` (ARM) attribute is **present and set to any non-empty value**. It does not validate which specific encryption set is referenced, only that customer-managed key encryption has been configured at all. If the attribute is absent, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_managed_disk" "example" {
  name                 = "example-disk"
  location             = azurerm_resource_group.example.location
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 32
  # no disk_encryption_set_id -> uses platform-managed key only
}
```

## Remediated example
```hcl
resource "azurerm_disk_encryption_set" "example" {
  name                = "example-des"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  key_vault_key_id    = azurerm_key_vault_key.example.id

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_managed_disk" "example" {
  name                 = "example-disk"
  location             = azurerm_resource_group.example.location
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 32

  disk_encryption_set_id = azurerm_disk_encryption_set.example.id  # <-- customer-managed key
}
```

## Remediation steps
1. Create (or reuse) an Azure Key Vault key dedicated to disk encryption.
2. Create an `azurerm_disk_encryption_set` resource referencing that key, with a managed identity.
3. Grant the Disk Encryption Set's managed identity the `Key Vault Crypto Service Encryption User` role (or equivalent access policy) on the Key Vault.
4. Set `disk_encryption_set_id` on the managed disk to the Disk Encryption Set's ID.
5. Note: associating a Disk Encryption Set with an existing disk typically requires the VM to be deallocated first — plan for a maintenance window. New disks can be created directly with the encryption set attached with no downtime.
6. Establish a key rotation policy in Key Vault and confirm the Disk Encryption Set is configured for auto-rotation if required by your compliance program.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureManagedDiskEncryptionSet.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureManagedDiskEncryptionSet.py
