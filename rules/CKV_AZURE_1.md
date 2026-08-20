# CKV_AZURE_1: Ensure Azure Instance does not use basic authentication (Use SSH Key Instead)
## Severity
**HIGH** (score: 7.5/10)

Allowing password-based (basic) authentication on a VM instead of requiring SSH keys significantly increases exposure to credential brute-forcing and password-reuse attacks against the host.

## Summary
This check ensures that Azure Linux virtual machines require SSH key–based authentication instead of allowing password (basic) authentication for login.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_virtual_machine`, `azurerm_linux_virtual_machine`
- **ARM/Bicep**: `Microsoft.Compute/virtualMachines`

The check is skipped (returns `UNKNOWN`) for ARM templates whose `imageReference.publisher` indicates a Windows/Microsoft image, since password-based authentication is the normal mechanism for Windows.

## Why it matters
Password authentication over SSH is inherently weaker than public-key authentication: passwords can be guessed, brute-forced, phished, or reused across systems, whereas SSH key pairs use asymmetric cryptography that is effectively immune to online brute-force attacks and cannot be captured via credential-stuffing lists. Internet-facing or improperly segmented VMs with password auth enabled are a classic target for automated SSH brute-force botnets. Disabling password authentication and relying solely on SSH keys removes an entire class of credential-based attacks against the VM's management plane.

## How Checkov evaluates this
- **Terraform**: The check inspects `os_profile_linux_config[0].disable_password_authentication`. If this block is present and `disable_password_authentication` is explicitly `false`, the check **FAILS**. It also checks the top-level `disable_password_authentication` attribute (used by `azurerm_linux_virtual_machine`); if that value is falsy, it **FAILS**. Any other combination (attribute absent, or set to `true`) **PASSES**.
- **ARM**: Uses `properties/osProfile/linuxConfiguration/disablePasswordAuthentication` and expects it to equal `true`. Before evaluating, it inspects `properties/storageProfile/imageReference/publisher`; if the publisher string contains "windows" or "microsoft" (case-insensitive), the check is marked `UNKNOWN` (not applicable) since this is a Windows image.

## Non-compliant example
```hcl
resource "azurerm_linux_virtual_machine" "bad_example" {
  name                = "bad-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_F2"
  admin_username      = "adminuser"
  admin_password      = "P@ssw0rd1234!"

  disable_password_authentication = false

  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]

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
resource "azurerm_linux_virtual_machine" "good_example" {
  name                = "good-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_F2"
  admin_username      = "adminuser"

  # Fix: disable password auth and use an SSH key instead
  disable_password_authentication = true

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]

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
1. Set `disable_password_authentication = true` (or omit `admin_password` and rely on the resource default) on `azurerm_linux_virtual_machine`/`azurerm_virtual_machine`.
2. Add an `admin_ssh_key` block (or `os_profile_linux_config.ssh_keys` for the legacy `azurerm_virtual_machine` resource) referencing a valid RSA/ED25519 public key.
3. Remove any hard-coded `admin_password` values from source control; if a password is required for break-glass access, store it in Azure Key Vault instead.
4. For existing VMs, this change typically requires re-provisioning the VM (or at minimum modifying `/etc/ssh/sshd_config` out-of-band) — plan for a maintenance window.
5. This check does not apply to Windows VMs; no action is needed there.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureInstancePassword.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureInstancePassword.py)
- [Azure docs: Detailed steps to create and manage SSH keys](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/mac-create-ssh-keys)
