# CKV_AZURE_92: Ensure that Virtual Machines use managed disks
## Severity
**LOW** (score: 2.0/10)

Unmanaged (VHD-based) disks lack the built-in encryption, access control, and resiliency guarantees of Azure managed disks, increasing exposure of VM disk data without representing an immediately exploitable path on its own.

## Summary
This check verifies that Azure Virtual Machines use managed disks rather than legacy unmanaged disks backed by a VHD file in a storage account.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_linux_virtual_machine`, `azurerm_windows_virtual_machine` (inspects `storage_os_disk`/`storage_data_disk` blocks for `vhd_uri`)
- **ARM templates**: `Microsoft.Compute/virtualMachines` (inspects `properties.storageProfile.osDisk`/`dataDisks` for a `vhd` key)
- **Bicep**: resources compiling to `Microsoft.Compute/virtualMachines`

## Why it matters
Unmanaged disks store VM disk images as page blobs (VHD files) directly inside a storage account that you must provision and manage yourself. This creates several operational and security risks:
- **Availability**: Unmanaged disks do not benefit from Azure's disk-level availability guarantees or automatic placement across Availability Sets — multiple VM disks stored in the same storage account can share fault/update domains, undermining the redundancy an Availability Set is supposed to provide (storage account IOPS/throughput limits can also be silently exhausted).
- **Access control granularity**: Access to unmanaged disks is governed by storage account keys/SAS tokens rather than Azure RBAC at the disk resource level, making it harder to apply least-privilege access control and audit who can read/write disk contents.
- **Encryption and key management**: Managed disks integrate cleanly with Azure Disk Encryption and customer-managed keys via Disk Encryption Sets; unmanaged disks require separately managing storage account encryption settings, which is easy to overlook.
- **Operational risk**: Storage account name/key rotation, quota limits, and manual VHD blob management introduce more moving parts that can be misconfigured compared to the fully Azure-managed disk lifecycle.

Managed disks eliminate this entire class of storage-account-management risk by having Azure handle placement, replication, and encryption transparently.

## How Checkov evaluates this
- **Terraform**: Inspects the VM resource's `storage_os_disk` and `storage_data_disk` blocks. If either block contains a `vhd_uri` key, the check FAILS (this indicates an unmanaged disk pointing at a blob URI). If neither disk block is present, or present without `vhd_uri`, it PASSES. Note: `azurerm_linux_virtual_machine`/`azurerm_windows_virtual_machine` are the modern resources that only support managed disks by design — `vhd_uri` style unmanaged disks are really a legacy pattern from `azurerm_virtual_machine`.
- **ARM**: Inspects `properties.storageProfile.osDisk` and each entry in `dataDisks`. If the `osDisk` dict contains a `vhd` key, or any `dataDisks` entry contains a `vhd` key, it FAILS. Absent `vhd`, or absent `storageProfile`/`properties` entirely, it PASSES.

## Non-compliant example
```json
{
  "type": "Microsoft.Compute/virtualMachines",
  "apiVersion": "2022-03-01",
  "name": "example-vm",
  "properties": {
    "storageProfile": {
      "osDisk": {
        "name": "example-osdisk",
        "createOption": "FromImage",
        "vhd": {
          "uri": "https://examplestorage.blob.core.windows.net/vhds/osdisk.vhd"
        }
      }
    }
  }
}
```

## Remediated example
```json
{
  "type": "Microsoft.Compute/virtualMachines",
  "apiVersion": "2022-03-01",
  "name": "example-vm",
  "properties": {
    "storageProfile": {
      "osDisk": {
        "name": "example-osdisk",
        "createOption": "FromImage",
        "managedDisk": {
          "storageAccountType": "Premium_LRS"
        }
      }
    }
  }
}
```

## Remediation steps
1. Remove the `vhd`/`vhd_uri` reference from the OS disk and any data disk blocks.
2. Add a `managedDisk` block (ARM/Bicep) specifying a `storageAccountType` (e.g. `Standard_LRS`, `Premium_LRS`), or in Terraform simply omit `storage_os_disk`/`storage_data_disk` and use `azurerm_managed_disk` resources with `azurerm_virtual_machine_data_disk_attachment` for extra data disks — the modern `azurerm_linux_virtual_machine`/`azurerm_windows_virtual_machine` resources use managed disks by default.
3. Migrating an existing unmanaged-disk VM to managed disks requires a conversion step (e.g. `az vm convert` or recreating the VM) — this typically requires a maintenance window and VM downtime/deallocation.
4. After migration, verify backup/DR tooling (e.g. Azure Backup, Azure Site Recovery) is re-pointed at the new managed disk resources.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMStorageOsDisk.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/VMStorageOsDisk.py
