# CKV_AZURE_149: Ensure that Virtual machine does not enable password authentication

## Severity
**LOW** (score: 2.0/10)

Enabling password authentication on a Linux VM opens it to brute-force and credential-stuffing attacks over SSH, a common initial-access vector, in place of much stronger key-based auth.

## Summary
This check ensures that Linux virtual machines (and scale sets) in Azure are configured to disable password-based SSH authentication, forcing use of SSH key-based authentication instead.

## Applicability
- **Frameworks:** Terraform, Bicep, ARM
- **Resource types:**
  - Terraform: `azurerm_linux_virtual_machine`, `azurerm_linux_virtual_machine_scale_set`
  - ARM/Bicep: `Microsoft.Compute/virtualMachines`, `Microsoft.Compute/virtualMachineScaleSets`

## Why it matters
Password authentication over SSH is inherently weaker than key-based authentication: passwords can be brute-forced, guessed, phished, or reused across systems, and they are far more susceptible to credential-stuffing attacks than a properly protected private key. Internet-facing or improperly segmented VMs with password auth enabled are a common initial-access vector for automated SSH brute-force botnets. Disabling password authentication and relying solely on SSH keys removes an entire class of remote-access attacks and enforces stronger, non-reusable credential material.

## How Checkov evaluates this
**Terraform** (`VMDisablePasswordAuthentication`, a `BaseResourceNegativeValueCheck`):
- Inspects `disable_password_authentication` on `azurerm_linux_virtual_machine` / `azurerm_linux_virtual_machine_scale_set`.
- **FAIL** if this attribute is explicitly set to `false` (the forbidden value).
- **PASS** otherwise — note that the Terraform azurerm provider defaults `disable_password_authentication` to `true`, so omitting it passes.

**ARM/Bicep** (`VMDisablePasswordAuthentication`, a `BaseResourceCheck`):
- Looks at `properties.osProfile.linuxConfiguration.disablePasswordAuthentication` for `Microsoft.Compute/virtualMachines`, or the equivalent path under `properties.virtualMachineProfile.osProfile.linuxConfiguration` for scale sets.
- **PASS** only if `disablePasswordAuthentication` is boolean `true`.
- **FAIL** if `linuxConfiguration` exists but `disablePasswordAuthentication` is missing/falsy.
- **UNKNOWN** if `osProfile` (or `linuxConfiguration`) cannot be found at all (e.g. Windows VM or missing profile).
- **FAIL** if the `properties` block itself is missing.

## Non-compliant example
```hcl
resource "azurerm_linux_virtual_machine" "example" {
  name                            = "example-vm"
  resource_group_name             = azurerm_resource_group.example.name
  location                        = azurerm_resource_group.example.location
  size                            = "Standard_B1s"
  admin_username                  = "adminuser"
  admin_password                  = "P@ssw0rd1234!"
  disable_password_authentication = false   # allows password-based SSH login

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
  name                            = "example-vm"
  resource_group_name             = azurerm_resource_group.example.name
  location                        = azurerm_resource_group.example.location
  size                            = "Standard_B1s"
  admin_username                  = "adminuser"
  disable_password_authentication = true    # enforces SSH key-only authentication

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
1. Set `disable_password_authentication = true` (Terraform) or `disablePasswordAuthentication: true` under `osProfile.linuxConfiguration` (ARM/Bicep).
2. Provide an `admin_ssh_key` block (Terraform) or `linuxConfiguration.ssh.publicKeys` (ARM/Bicep) with a valid public key, since password auth can no longer be used to log in.
3. Remove any `admin_password` attribute — it's not needed and conflicts with the security intent.
4. This setting can typically only be applied at VM creation; changing it on an existing VM may require recreating the resource (`disable_password_authentication` forces replacement in the Terraform azurerm provider for some versions) — plan for downtime or use `create_before_destroy`.
5. Ensure operational tooling (bastion hosts, automation, CI/CD) is updated to use SSH keys instead of passwords before rolling this out broadly.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMDisablePasswordAuthentication.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/VMDisablePasswordAuthentication.py)
- [Azure Linux VM SSH documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/mac-create-ssh-keys)
