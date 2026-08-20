# CKV2_AZURE_9: Ensure Virtual Machines are utilizing Managed Disks

## Severity
**LOW** (score: 2.0/10)

Using unmanaged disks instead of Azure Managed Disks is primarily an operational/reliability and management-hygiene concern (backup, encryption-key management consistency) rather than a direct, exploitable security exposure.

## Summary
This check verifies that Azure Virtual Machines defined via the (classic) `azurerm_virtual_machine` resource use Managed Disks rather than unmanaged disks backed directly by a storage account blob (VHD).

## Applicability
- **Terraform**: `azurerm_virtual_machine` (the legacy/classic VM resource; the newer `azurerm_linux_virtual_machine`/`azurerm_windows_virtual_machine` resources always use managed disks and are out of scope for this check)

This is a graph-based attribute check on the `storage_os_disk` block.

## Why it matters
Unmanaged disks store VM disk data as page blobs in a storage account that you must provision and manage yourself. This creates several security and reliability risks: the storage account and its keys become an additional credential/attack surface that must be separately locked down (unlike managed disks, which are natively integrated with Azure RBAC and Azure Disk Encryption); unmanaged disks lack the same built-in resiliency guarantees (Azure documents higher failure/IOPS-throttling risk when many unmanaged disks share a storage account, since storage account IOPS limits are shared across all VHDs in the account); and unmanaged disks do not support many modern features (Azure Backup integration, incremental snapshots, disk encryption sets, availability zone pinning) that are essential for a robust security and DR posture. Migrating to managed disks removes an entire class of manual storage-account security configuration that is easy to get wrong.

## How Checkov evaluates this
Implemented as a JSON graph query on resource attributes.

- FAIL: `azurerm_virtual_machine.storage_os_disk` has a `vhd_uri` attribute set (indicating an unmanaged disk pointing at a blob URI), or lacks a `managed_disk_type` attribute.
- PASS: `storage_os_disk.managed_disk_type` exists (e.g. `"Standard_LRS"`, `"Premium_LRS"`) AND `storage_os_disk.vhd_uri` does not exist.

## Non-compliant example
```hcl
resource "azurerm_virtual_machine" "example" {
  name                  = "example-vm"
  location              = azurerm_resource_group.example.location
  resource_group_name   = azurerm_resource_group.example.name
  network_interface_ids = [azurerm_network_interface.example.id]
  vm_size               = "Standard_DS1_v2"

  storage_os_disk {
    name          = "example-osdisk"
    caching       = "ReadWrite"
    create_option = "FromImage"
    vhd_uri       = "${azurerm_storage_account.example.primary_blob_endpoint}vhds/osdisk.vhd"  # unmanaged disk -> FAILS
  }

  storage_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}
```

## Remediated example
```hcl
resource "azurerm_virtual_machine" "example" {
  name                  = "example-vm"
  location              = azurerm_resource_group.example.location
  resource_group_name   = azurerm_resource_group.example.name
  network_interface_ids = [azurerm_network_interface.example.id]
  vm_size               = "Standard_DS1_v2"

  storage_os_disk {
    name              = "example-osdisk"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Standard_LRS"   # fixed: managed disk, no vhd_uri
  }

  storage_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}
```

## Remediation steps
1. Remove `vhd_uri` from the `storage_os_disk` (and any `storage_data_disk`) blocks.
2. Add `managed_disk_type` set to your desired SKU (`Standard_LRS`, `StandardSSD_LRS`, `Premium_LRS`, etc.).
3. **Caveat**: converting an already-deployed unmanaged-disk VM to managed disks generally requires deallocating the VM and running an in-place conversion (`az vm convert`) or recreating the VM — it is not a simple in-place Terraform attribute change for existing infrastructure, and may cause downtime.
4. Prefer migrating entirely off the legacy `azurerm_virtual_machine` resource to `azurerm_linux_virtual_machine` / `azurerm_windows_virtual_machine`, which use managed disks exclusively and receive ongoing feature support from HashiCorp/Microsoft.
5. Once on managed disks, consider enabling Azure Disk Encryption or platform-managed/customer-managed disk encryption sets for additional at-rest protection.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/VirtualMachinesUtilizingManagedDisks.json)
- [Azure Managed Disks overview](https://learn.microsoft.com/en-us/azure/virtual-machines/managed-disks-overview)
