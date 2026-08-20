# CKV_AZURE_49: Ensure Azure linux scale set does not use basic authentication (Use SSH Key Instead)

## Severity
**HIGH** (score: 7.5/10)

Allowing password-based (basic) authentication on Linux VM scale set instances instead of requiring SSH keys exposes instances to credential-guessing and brute-force attacks, a materially weaker authentication mechanism at scale.

## Summary
This check verifies that a Linux Virtual Machine Scale Set has password-based SSH authentication disabled, requiring SSH key-based authentication instead.

## Applicability
- **Terraform**: `azurerm_linux_virtual_machine_scale_set`
- **ARM templates**: `Microsoft.Compute/virtualMachineScaleSets`
- **Bicep**: `Microsoft.Compute/virtualMachineScaleSets`

## Why it matters
Password authentication over SSH is inherently weaker than public-key authentication: passwords can be brute-forced, guessed, phished, or reused across systems, whereas SSH key pairs require possession of a private key that is computationally infeasible to guess and never transmitted over the network during authentication. Virtual Machine Scale Sets are especially attractive brute-force targets because they represent fleets of identically configured instances — a single compromised or weak password affects every instance provisioned from that scale set model, and internet-facing scale sets are routinely scanned for SSH login attempts. Disabling password authentication removes an entire class of credential-guessing and credential-stuffing attacks against the fleet.

## How Checkov evaluates this
- **Both ARM and Terraform**: This check first special-cases Windows: if the VM/scale-set image publisher name contains `"windows"` (case-insensitive), the check returns `UNKNOWN` since password authentication is the normal/expected mechanism for Windows and this check is Linux-specific. Otherwise, it inspects `properties.virtualMachineProfile.osProfile.linuxConfiguration.disablePasswordAuthentication` (ARM) or `disable_password_authentication` (Terraform, nested one level under the scale set's OS profile in provider schema). PASSES only if that value is `true`.

## Non-compliant example
```hcl
resource "azurerm_linux_virtual_machine_scale_set" "example" {
  name                = "example-vmss"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard_F2"
  instances           = 3

  admin_username                 = "adminuser"
  admin_password                 = var.admin_password
  disable_password_authentication = false

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  os_disk {
    storage_account_type = "Standard_LRS"
    caching               = "ReadWrite"
  }

  network_interface {
    name    = "example-nic"
    primary = true

    ip_configuration {
      name      = "internal"
      primary   = true
      subnet_id = azurerm_subnet.example.id
    }
  }
}
```

## Remediated example
```hcl
resource "azurerm_linux_virtual_machine_scale_set" "example" {
  name                = "example-vmss"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard_F2"
  instances           = 3

  admin_username                   = "adminuser"
  disable_password_authentication = true

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  os_disk {
    storage_account_type = "Standard_LRS"
    caching               = "ReadWrite"
  }

  network_interface {
    name    = "example-nic"
    primary = true

    ip_configuration {
      name      = "internal"
      primary   = true
      subnet_id = azurerm_subnet.example.id
    }
  }
}
```

## Remediation steps
1. Set `disable_password_authentication = true` on the `azurerm_linux_virtual_machine_scale_set` resource (or `properties.virtualMachineProfile.osProfile.linuxConfiguration.disablePasswordAuthentication = true` in ARM/Bicep).
2. Add an `admin_ssh_key` block with a valid public key instead of (or in addition to removing) `admin_password`.
3. Distribute and manage the corresponding private key securely — consider Azure Key Vault or a secrets manager for storing/rotating the SSH key pair used by automation.
4. This setting is only relevant to Linux images — Windows-based scale sets are not applicable and Checkov will report `UNKNOWN` for those, not a failure.
5. Changing this setting on an existing scale set may require instance model updates/rolling upgrades to propagate to running instances; plan for a coordinated rollout.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureScaleSetPassword.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureScaleSetPassword.py)
- [Azure VMSS Linux authentication documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/mac-create-ssh-keys)
