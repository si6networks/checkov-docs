# CKV_AZURE_2: Ensure Azure managed disk have encryption enabled

## Severity
**LOW** (score: 2.0/10)

Managed disks hold VM OS/application data and secrets, and while Azure applies platform-managed encryption by default, an explicitly disabled encryption_settings block (or, for ARM, any missing encryption configuration) can leave data exposed to anyone with storage-layer access.

## Summary
This check ensures Azure managed disks have disk encryption enabled (either via a disk encryption set, encryption settings block, or, for ARM templates, an `encryption`/`encryptionSettings(Collection)` property), so data at rest on the disk is protected.

## Applicability
- **Frameworks:** Terraform, ARM templates, Bicep (Bicep compiles to ARM JSON and is evaluated by the same ARM check)
- **Resource types:** `azurerm_managed_disk` (Terraform), `Microsoft.Compute/disks` (ARM/Bicep)

## Why it matters
Managed disks store the persistent state of VMs — OS volumes, application data, databases, secrets baked into images, and swap/temp data. If a disk is not encrypted at rest, anyone who gains access to the underlying storage medium (through an Azure platform vulnerability, a misconfigured disk export/snapshot shared too broadly, disk theft/decommissioning failures, or an insider with storage-layer access) can read raw disk contents without needing to authenticate to the VM or application. Azure disk encryption (Server-Side Encryption with platform-managed or customer-managed keys, or Azure Disk Encryption using BitLocker/DM-Crypt) ensures data remains confidential even if the storage layer itself is compromised, which is a baseline expectation for handling regulated or sensitive data.

## How Checkov evaluates this
**Terraform (`azurerm_managed_disk`)** — custom `scan_resource_conf` logic:
- PASSES if `disk_encryption_set_id` is present (customer-managed encryption via a Disk Encryption Set).
- Else, if `encryption_settings` block exists: PASSES if `encryption_settings[0].enabled == true`, otherwise FAILS.
- If no `encryption_settings` block and no `disk_encryption_set_id` at all: PASSES by default — Azure managed disks are encrypted at rest by default with platform-managed keys, so absence of these attributes is not a failure.

**ARM/Bicep (`Microsoft.Compute/disks`)** — custom `scan_resource_conf` logic:
- Looks at `properties.encryption` — if this block exists at all, PASSES (presence implies encryption is configured).
- Else checks `properties.encryptionSettingsCollection.enabled` — PASSES if `"true"` (string-compared, case-insensitive).
- Else checks the legacy `properties.encryptionSettings.enabled` — PASSES if `"true"`.
- If none of the above are found, FAILS (unlike the Terraform version, the ARM check has no "encrypted by default" fallback — it requires explicit `properties` matching one of the conditions).

## Non-compliant example
```hcl
# Terraform - fails only because encryption_settings is explicitly disabled
resource "azurerm_managed_disk" "example" {
  name                 = "example-disk"
  location             = azurerm_resource_group.example.location
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 128

  encryption_settings {
    enabled = false
  }
}
```

```json
// ARM template - fails: no encryption/encryptionSettings(Collection) properties present
{
  "type": "Microsoft.Compute/disks",
  "apiVersion": "2022-03-02",
  "name": "example-disk",
  "location": "eastus",
  "properties": {
    "creationData": {
      "createOption": "Empty"
    },
    "diskSizeGB": 128
  }
}
```

## Remediated example
```hcl
# Terraform - use a customer-managed Disk Encryption Set
resource "azurerm_managed_disk" "example" {
  name                 = "example-disk"
  location             = azurerm_resource_group.example.location
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 128

  disk_encryption_set_id = azurerm_disk_encryption_set.example.id
}
```

```json
// ARM template - add explicit encryption property
{
  "type": "Microsoft.Compute/disks",
  "apiVersion": "2022-03-02",
  "name": "example-disk",
  "location": "eastus",
  "properties": {
    "creationData": {
      "createOption": "Empty"
    },
    "diskSizeGB": 128,
    "encryption": {
      "type": "EncryptionAtRestWithPlatformKey"
    }
  }
}
```

## Remediation steps
1. Prefer customer-managed keys via `azurerm_disk_encryption_set` (Terraform) or an `encryption` property block referencing a Disk Encryption Set (ARM) for the strongest control over key lifecycle and rotation.
2. If using the legacy `encryption_settings` block in Terraform, ensure `enabled = true` — do not leave it explicitly disabled.
3. For ARM/Bicep, always populate the `properties.encryption` (or `encryptionSettingsCollection`) block rather than omitting it, since the ARM check has no implicit pass for a bare `properties` object.
4. Adding a Disk Encryption Set to an existing unencrypted disk may require the disk to be detached/reattached or the VM to be stopped, depending on disk state — plan for a maintenance window.
5. Ensure the Key Vault backing the Disk Encryption Set has soft-delete and purge protection enabled; losing the key makes the disk permanently unreadable.

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureManagedDiskEncryption.py)
- [Checkov ARM check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureManagedDiscEncryption.py)
- [Azure Disk Encryption documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview)
