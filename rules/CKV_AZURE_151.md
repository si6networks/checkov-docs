# CKV_AZURE_151: Ensure Windows VM enables encryption

## Severity
**LOW** (score: 2.0/10)

Without host-based encryption, data on a Windows VM's OS, data, and temp disks is stored unencrypted, exposing it to compromise if the underlying storage or host is accessed outside the VM's own controls.

## Summary
This check ensures that an Azure Windows Virtual Machine has encryption-at-host enabled, so that all disks attached to the VM — including the OS disk, data disks, and the ephemeral temp disk — are encrypted at rest on the host infrastructure.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, Bicep, ARM
- **Resource types:**
  - Terraform: `azurerm_windows_virtual_machine`
  - ARM/Bicep: `Microsoft.Compute/virtualMachines`

## Why it matters
By default, Azure Disk Encryption / Storage Service Encryption only protects managed disks, not the temporary (ephemeral) disk attached to a VM, nor caching data on the host. Encryption at host closes this gap by encrypting all data at rest at the host level, including the temp disk and any disk caches, ensuring data is protected end-to-end even if physical storage media is later accessed or repurposed. Without this setting, sensitive data written to temp/cache storage (e.g. page files, application scratch data, cached credentials) could persist unencrypted on the underlying host storage, which is a real gap for compliance regimes (e.g. HIPAA, PCI-DSS) that require encryption of all data at rest.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Terraform:** inspects `encryption_at_host_enabled` on `azurerm_windows_virtual_machine`.
- **ARM/Bicep:** inspects `properties.securityProfile.encryptionAtHost`.
- **PASS** if the value is `true`.
- **FAIL** if the value is `false`, or the attribute is absent (default missing-block behavior for `BaseResourceValueCheck` is FAILED).

## Non-compliant example
```hcl
resource "azurerm_windows_virtual_machine" "example" {
  name                = "example-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_D2s_v3"
  admin_username      = "adminuser"
  admin_password      = "P@ssw0rd1234!"

  # encryption_at_host_enabled omitted -> temp/cache disks left unencrypted at host

  network_interface_ids = [azurerm_network_interface.example.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-Datacenter"
    version   = "latest"
  }
}
```

## Remediated example
```hcl
resource "azurerm_windows_virtual_machine" "example" {
  name                = "example-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_D2s_v3"
  admin_username      = "adminuser"
  admin_password      = "P@ssw0rd1234!"

  encryption_at_host_enabled = true   # encrypts OS, data, and temp disks at host

  network_interface_ids = [azurerm_network_interface.example.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-Datacenter"
    version   = "latest"
  }
}
```

## Remediation steps
1. Set `encryption_at_host_enabled = true` (Terraform) or `properties.securityProfile.encryptionAtHost: true` (ARM/Bicep) on the VM resource.
2. Encryption at host must first be enabled at the subscription level (`az feature register --namespace Microsoft.Compute --name EncryptionAtHost`) before it can be used on VM resources — verify the feature is registered, or deployment will fail.
3. Check that the chosen VM size supports encryption at host; not all VM SKUs do.
4. This setting generally can only be set at VM creation time; enabling it on an existing VM may require deallocating/recreating the VM — plan for a maintenance window.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/WinVMEncryptionAtHost.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/WinVMEncryptionAtHost.py)
- [Azure encryption-at-host documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/disks-enable-host-based-encryption-portal)
