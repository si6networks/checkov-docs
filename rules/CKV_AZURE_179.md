# CKV_AZURE_179: Ensure VM agent is installed

## Severity
**LOW** (score: 2.0/10)

Without the VM agent, the platform loses the ability to apply extensions used for patching, monitoring, and security agent deployment, indirectly weakening the VM's ongoing security posture rather than creating a direct exploit path.

## Summary
This check ensures that the Azure VM Guest Agent (`provision_vm_agent`) is enabled on Windows and Linux virtual machines and scale sets, rather than explicitly disabled.

## Applicability
- **Terraform**: `azurerm_windows_virtual_machine`, `azurerm_windows_virtual_machine_scale_set`, `azurerm_linux_virtual_machine`, `azurerm_linux_virtual_machine_scale_set` (`provision_vm_agent`).

## Why it matters
The Azure VM Agent is the in-guest component that enables extensions — Azure Monitor Agent, Microsoft Defender for Cloud endpoint protection, Update Manager/patch orchestration, disk encryption extensions, custom script extensions, and more. Disabling `provision_vm_agent` prevents any of these extensions from being installed or functioning, which means the VM cannot receive centrally-managed security monitoring, vulnerability scanning, automated patching, or incident-response tooling deployed via Azure's extension framework. In effect, disabling the agent creates a blind spot: the VM becomes invisible to Azure-native security and compliance tooling, undermining detection and response capability for that host even if the workload itself is otherwise fine.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` with `missing_block_result=PASSED` (the attribute defaults to enabled/`true` if unset, matching Azure's own default). It inspects the `provision_vm_agent` attribute and **FAILS** only when it is explicitly set to `false`; when absent or `true`, the check **PASSES**.

## Non-compliant example
```hcl
resource "azurerm_linux_virtual_machine" "vm" {
  name                = "my-linux-vm"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_D2s_v3"
  admin_username      = "adminuser"

  provision_vm_agent = false

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  network_interface_ids = [azurerm_network_interface.nic.id]

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
resource "azurerm_linux_virtual_machine" "vm" {
  name                = "my-linux-vm"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_D2s_v3"
  admin_username      = "adminuser"

  provision_vm_agent = true

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  network_interface_ids = [azurerm_network_interface.nic.id]

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
1. Remove any explicit `provision_vm_agent = false`, or set it to `true`.
2. `provision_vm_agent` is set at VM/image-provisioning time and is a `ForceNew` attribute in the Terraform provider — changing it on an existing VM requires replacement.
3. After enabling, deploy the security/monitoring extensions your organization requires (Microsoft Defender for Cloud, Azure Monitor Agent, Update Manager) since enabling the agent alone doesn't install any specific extension.
4. If a VM genuinely must run without the guest agent (rare, e.g. certain appliance images that manage their own lifecycle), document the exception and ensure equivalent monitoring is achieved out-of-band.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMAgentIsInstalled.py
- Microsoft Docs: https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/agent-windows
