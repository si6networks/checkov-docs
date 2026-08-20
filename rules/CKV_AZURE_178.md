# CKV_AZURE_178: Ensure linux VM enables SSH with keys for secure communication

## Severity
**HIGH** (score: 7.5/10)

A Linux VM without an SSH key configured is left relying on (or defaulting toward) password authentication for a privileged administrative entry point, which is materially more susceptible to brute-force and credential-stuffing attacks than key-based auth.

## Summary
This check ensures that Linux Azure Virtual Machines and VM Scale Sets are configured with an SSH public key for authentication, rather than relying only on password-based login.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_linux_virtual_machine`, `azurerm_linux_virtual_machine_scale_set` (`admin_ssh_key[0].public_key`).
- **ARM/Bicep**: `Microsoft.Compute/virtualMachines`, `Microsoft.Compute/virtualMachineScaleSets` (`properties.osProfile.linuxConfiguration.ssh.publicKeys[0].path` / VMSS equivalent).

## Why it matters
Password-based SSH authentication is inherently weaker than key-based authentication: passwords can be brute-forced or guessed (especially over the internet, where automated scanners constantly probe port 22 with credential-stuffing dictionaries), can be reused across systems, and can be phished. SSH key pairs, by contrast, require possession of a private key that never leaves the client and is not transmitted during authentication, making remote brute-force and credential-replay attacks against the login mechanism impractical. A Linux VM without a configured SSH public key is either relying on a password (if `disable_password_authentication` is off) or, at minimum, is missing the more robust authentication path entirely — either way it's a materially weaker access-control posture on a system that is frequently a privileged administrative entry point.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using `ANY_VALUE` as the expected value, meaning it just requires the SSH public key path to be **present and non-empty**:
- **Terraform** inspects `admin_ssh_key/[0]/public_key`.
- **ARM** inspects `properties/osProfile/linuxConfiguration/ssh/publicKeys/[0]/path` (VMs) or the equivalent path under `virtualMachineProfile` for scale sets.

If no SSH key entry is found, the check **FAILS**.

## Non-compliant example
```hcl
resource "azurerm_linux_virtual_machine" "vm" {
  name                            = "my-linux-vm"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  size                            = "Standard_D2s_v3"
  admin_username                  = "adminuser"
  admin_password                  = var.admin_password
  disable_password_authentication = false
  # No admin_ssh_key block configured

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
  name                            = "my-linux-vm"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  size                            = "Standard_D2s_v3"
  admin_username                  = "adminuser"
  disable_password_authentication = true

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
1. Add an `admin_ssh_key` block specifying `username` and `public_key` (the SSH public key, never the private key).
2. Set `disable_password_authentication = true` to fully remove the weaker password-login path once key-based access is confirmed working.
3. For ARM/Bicep, populate `linuxConfiguration.ssh.publicKeys` with the key path and value, and set `disablePasswordAuthentication: true`.
4. Manage private key distribution securely (per-admin keys, not a shared key) and rotate/revoke keys via an update to the `admin_ssh_key`/`publicKeys` list when personnel change.
5. Both `admin_ssh_key` and `admin_password`/`disable_password_authentication` are typically set at VM creation and may require replacement to change after the fact — plan accordingly for existing VMs.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/LinuxVMUsesSSH.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/LinuxVMUsesSSH.py
