# CKV_AZURE_50: Ensure Virtual Machine Extensions are not Installed

## Severity
**MEDIUM** (score: 5.0/10)

Allowing VM extension operations lets anyone with sufficient Azure RBAC rights install extensions that execute arbitrary, highly privileged code on the virtual machine, a real path to code execution and privilege escalation.

## Summary
This check verifies that Azure Virtual Machines have `allowExtensionOperations` (VM extension operations) disabled, preventing arbitrary VM extensions from being installed on the instance.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_linux_virtual_machine`, `azurerm_windows_virtual_machine`
- **ARM templates**: `Microsoft.Compute/virtualMachines`
- **Bicep**: `Microsoft.Compute/virtualMachines`

## Why it matters
VM extensions run with high privilege inside the guest OS and can execute arbitrary scripts, install software, or reconfigure the system (Custom Script Extension, VM Access extension for resetting credentials, etc.). Any principal with sufficient Azure RBAC permissions to manage the VM resource (e.g., `Microsoft.Compute/virtualMachines/extensions/write`) — which may be a broader set of people/service principals than those who should have OS-level access — can leverage extensions to run code inside the VM, effectively bypassing OS-level access controls and audit boundaries. Disabling extension operations closes off this privilege-escalation path: it ensures that Azure control-plane access alone (without direct OS credentials) cannot be used to execute arbitrary commands inside the VM, which is important in environments where Azure RBAC and OS access are meant to be separate trust boundaries.

## How Checkov evaluates this
This is a straightforward generic value check:
- **ARM**: Inspects `properties.osProfile.allowExtensionOperations`. PASSES only if it is exactly `false`.
- **Terraform**: Inspects `allow_extension_operations`. PASSES only if it is `false`.

## Non-compliant example
```hcl
resource "azurerm_linux_virtual_machine" "example" {
  name                = "example-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_F2"
  admin_username      = "adminuser"

  allow_extension_operations = true

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  network_interface_ids = [azurerm_network_interface.example.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}
```

## Remediated example
```hcl
resource "azurerm_linux_virtual_machine" "example" {
  name                = "example-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_F2"
  admin_username      = "adminuser"

  allow_extension_operations = false

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  network_interface_ids = [azurerm_network_interface.example.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}
```

## Remediation steps
1. Set `allow_extension_operations = false` on the `azurerm_linux_virtual_machine`/`azurerm_windows_virtual_machine` resource, or `properties.osProfile.allowExtensionOperations = false` in ARM/Bicep.
2. **Caveat**: this will block legitimate extensions too — Azure Monitor Agent, Azure Backup, Azure Disk Encryption, and many diagnostic/monitoring extensions rely on this mechanism. Before disabling, confirm your operational tooling does not depend on VM extensions, or plan alternative deployment mechanisms (e.g., cloud-init/custom_data at initial provisioning, or agent-based monitoring installed via the base image instead of a post-deploy extension).
3. This is a reasonable control primarily for high-security workloads (e.g., PCI cardholder data environment VMs, or VMs where Azure control-plane RBAC and OS-level access are intentionally separated trust domains) — evaluate whether it's appropriate for every VM in your estate versus only the most sensitive ones.
4. This setting can generally be changed without VM replacement, but changing it after extensions are already installed does not retroactively remove them.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureInstanceExtensions.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureInstanceExtensions.py)
- [Azure VM extensions overview](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/overview)
