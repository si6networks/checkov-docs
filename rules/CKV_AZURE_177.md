# CKV_AZURE_177: Ensure Windows VM enables automatic updates

## Severity
**MEDIUM** (score: 5.0/10)

Disabling automatic OS updates on a Windows VM leaves known, patched vulnerabilities unaddressed indefinitely unless a separate patch-management process is enforced, widening the window for exploitation of unpatched CVEs.

## Summary
This check ensures that Windows Azure Virtual Machines and VM Scale Sets have automatic OS updates enabled so security patches are applied without manual intervention.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_windows_virtual_machine`, `azurerm_windows_virtual_machine_scale_set` (`enable_automatic_updates`).
- **ARM/Bicep**: `Microsoft.Compute/virtualMachines`, `Microsoft.Compute/virtualMachineScaleSets` (`properties.osProfile.windowsConfiguration.enableAutomaticUpdates` / the VMSS equivalent under `virtualMachineProfile`).

## Why it matters
Windows VMs that don't automatically apply OS updates depend entirely on manual patch management processes, which in practice are frequently delayed, inconsistent across a fleet, or forgotten altogether — especially for scale sets with many ephemeral or short-lived instances. This leaves known, publicly disclosed vulnerabilities (which attackers actively scan for and exploit shortly after patch Tuesday disclosures) unpatched on internet- or network-reachable machines for extended periods, directly increasing the window of exposure to remote code execution and privilege escalation exploits targeting the OS. Enabling automatic updates ensures security patches land on a predictable cadence without relying on operational follow-through.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` with `missing_block_result=PASSED` — meaning if the relevant attribute is entirely absent, the check treats it as passing (since Azure's own default behavior for these resources is to enable automatic updates). It only **FAILS** when the attribute is explicitly present and set to `false`/disabled.
- **Terraform** inspects `enable_automatic_updates`.
- **ARM** inspects `properties.osProfile.windowsConfiguration.enableAutomaticUpdates` (VMs) or `properties.virtualMachineProfile.osProfile.windowsConfiguration.enableAutomaticUpdates` (scale sets).

## Non-compliant example
```hcl
resource "azurerm_windows_virtual_machine" "vm" {
  name                = "my-win-vm"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_D2s_v3"
  admin_username      = "adminuser"
  admin_password      = var.admin_password

  enable_automatic_updates = false

  network_interface_ids = [azurerm_network_interface.nic.id]

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
resource "azurerm_windows_virtual_machine" "vm" {
  name                = "my-win-vm"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_D2s_v3"
  admin_username      = "adminuser"
  admin_password      = var.admin_password

  enable_automatic_updates = true

  network_interface_ids = [azurerm_network_interface.nic.id]

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
1. Remove any explicit `enable_automatic_updates = false` (or simply omit the attribute to inherit the secure default), or set it to `true` explicitly for clarity.
2. For ARM/Bicep, ensure `windowsConfiguration.enableAutomaticUpdates` is `true` (or omitted).
3. `enable_automatic_updates` is typically a `ForceNew` attribute in Terraform — changing it on an existing VM may require replacement; plan for a maintenance window.
4. Automatic Windows Update alone applies OS-level patches on Microsoft's schedule and reboot policy; for tighter control over patch timing/testing, consider Azure Update Manager instead of relying solely on in-guest Windows Update.
5. Combine with `patch_mode = "AutomaticByPlatform"` (where supported) for Azure-orchestrated patching with defined maintenance windows, rather than purely in-guest automatic updates.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/WinVMAutomaticUpdates.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/WinVMAutomaticUpdates.py
