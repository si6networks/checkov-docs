# CKV_AZURE_97: Ensure that Virtual machine scale sets have encryption at host enabled
## Severity
**LOW** (score: 2.0/10)

Without encryption at host, temporary disks, caches, and data flows between compute and storage resources are left unencrypted, exposing VM data to a host-level or storage-layer compromise.

## Summary
This check verifies that Azure Virtual Machines and Virtual Machine Scale Sets have "Encryption at Host" enabled, which encrypts temp disks and disk caches on the physical host, not just the managed disks themselves.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_linux_virtual_machine_scale_set`, `azurerm_windows_virtual_machine_scale_set` (inspects `encryption_at_host_enabled`)
- **ARM templates**: `Microsoft.Compute/virtualMachineScaleSets`, `Microsoft.Compute/virtualMachines` (inspects `properties.virtualMachineProfile.securityProfile.encryptionAtHost` for scale sets, and `properties.securityProfile.encryptionAtHost` for standalone VMs)
- **Bicep**: resources compiling to the above ARM types

## Why it matters
Standard Azure disk encryption (SSE) protects data at rest on managed disks, but it does **not** cover data that transiently lives outside the managed disk itself — specifically the VM's local/temp disk and the host-level disk caches used to accelerate read/write operations. Without Encryption at Host:
- Temporary disk contents (which can include swap files, application temp data, or cached secrets depending on workload) and disk caching data on the underlying physical host remain unencrypted.
- On a multi-tenant Azure host, if the underlying physical storage is ever improperly decommissioned, repurposed, or subject to a hardware-level compromise, unencrypted temp/cache data could theoretically be exposed — even though the persistent managed disk itself was encrypted.
- Compliance frameworks requiring end-to-end encryption of all VM-related storage (not just managed disks) cannot be satisfied without this setting.

Enabling Encryption at Host ensures that data flows through the entire host-level storage path — temp disks, OS/data disk caches, and the managed disks themselves — encrypted at rest, closing the gap left by managed-disk-only encryption.

## How Checkov evaluates this
Reads a nested key path from the resource configuration depending on entity type:
- For `Microsoft.Compute/virtualMachines`: `properties.securityProfile.encryptionAtHost`
- For `Microsoft.Compute/virtualMachineScaleSets`: `properties.virtualMachineProfile.securityProfile.encryptionAtHost`
- For Terraform (`azurerm_linux_virtual_machine_scale_set`/`azurerm_windows_virtual_machine_scale_set`): the `encryption_at_host_enabled` attribute directly.

The check PASSES only if the resolved value, compared case-insensitively as a string, equals `"true"`. Any other value (missing, `false`, or unparseable) results in FAILED.

## Non-compliant example
```hcl
resource "azurerm_linux_virtual_machine_scale_set" "example" {
  name                = "example-vmss"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard_F2"
  instances           = 2
  admin_username      = "adminuser"

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

  # encryption_at_host_enabled not set -> defaults to false
}
```

## Remediated example
```hcl
resource "azurerm_linux_virtual_machine_scale_set" "example" {
  name                = "example-vmss"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard_F2"
  instances           = 2
  admin_username      = "adminuser"

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

  encryption_at_host_enabled = true   # <-- encrypts temp disk and host caches too
}
```

## Remediation steps
1. Set `encryption_at_host_enabled = true` on the scale set resource (or the equivalent `securityProfile.encryptionAtHost` property in ARM/Bicep).
2. Encryption at Host must be enabled for the subscription first — register the `Microsoft.Compute` resource provider feature `EncryptionAtHost` via `az feature register` before it can be used on VMs/scale sets.
3. Not all VM sizes support Encryption at Host — verify your chosen SKU is on the supported list before enabling.
4. This is generally set at creation time; changing it on an existing scale set may require redeploying instances (rolling upgrade), so validate in a test environment first.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMEncryptionAtHostEnabled.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/VMEncryptionAtHostEnabled.py
