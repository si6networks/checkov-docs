# CKV_AZURE_95: Ensure that automatic OS image patching is enabled for Virtual Machine Scale Sets
## Severity
**LOW** (score: 2.0/10)

Without automatic OS image patching, VM Scale Set instances can drift out of date on security fixes over time, increasing the window during which known vulnerabilities remain exploitable.

## Summary
This check verifies that an Azure Virtual Machine Scale Set (VMSS) is configured to automatically apply OS image patches/upgrades to its instances rather than requiring manual intervention.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_virtual_machine_scale_set` (inspects `automatic_os_upgrade` and `os_profile_windows_config.enable_automatic_upgrades`)
- **ARM templates**: `Microsoft.Compute/virtualMachineScaleSets` (inspects extensions for `enableAutomaticUpgrade`, and the `orchestrationMode`)
- **Bicep**: resources compiling to `Microsoft.Compute/virtualMachineScaleSets`

## Why it matters
VM Scale Set instances run on OS images that require ongoing security patching (kernel vulnerabilities, OS-level CVEs, driver updates). Without automatic OS image upgrades configured:
- Instances continue running the OS image version they were originally deployed from indefinitely, even as new critical security patches for the base OS are released.
- Organizations must rely entirely on manual, ad-hoc patch management processes across potentially many scale-set instances — which are prone to drift, missed patch windows, and inconsistent state across the fleet.
- Unpatched instances remain vulnerable to known, publicly disclosed OS vulnerabilities for longer, increasing the window an attacker has to exploit them (e.g. via a known privilege-escalation or remote-code-execution CVE in the OS).

Automatic OS image patching keeps the fleet current with the latest secured OS image with minimal operational overhead, shrinking the exposure window for known vulnerabilities.

## How Checkov evaluates this
- **Terraform**: Checks that `automatic_os_upgrade` is truthy **and** an `os_profile_windows_config` block exists with `enable_automatic_upgrades` also truthy. Only if both conditions hold does the check PASS; otherwise it FAILS.
- **ARM**: If `properties.orchestrationMode == "Flexible"`, the check FAILS immediately (automatic OS upgrade via this mechanism isn't applicable/available the same way). Otherwise, it looks through `properties.virtualMachineProfile.extensionProfile.extensions` for any extension whose `properties.enableAutomaticUpgrade == true`. If found, PASSES; if no such extension is found, FAILS.

## Non-compliant example
```hcl
resource "azurerm_virtual_machine_scale_set" "example" {
  name                = "example-vmss"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku {
    name     = "Standard_F2"
    tier     = "Standard"
    capacity = 2
  }

  upgrade_policy_mode  = "Manual"
  # automatic_os_upgrade not set -> defaults to false, no auto patching

  os_profile {
    computer_name_prefix = "vmss"
    admin_username        = "adminuser"
    admin_password        = var.admin_password
  }

  os_profile_windows_config {
    enable_automatic_upgrades = false
  }
}
```

## Remediated example
```hcl
resource "azurerm_virtual_machine_scale_set" "example" {
  name                = "example-vmss"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku {
    name     = "Standard_F2"
    tier     = "Standard"
    capacity = 2
  }

  upgrade_policy_mode  = "Rolling"
  automatic_os_upgrade = true   # <-- enables automatic OS image upgrades

  os_profile {
    computer_name_prefix = "vmss"
    admin_username        = "adminuser"
    admin_password        = var.admin_password
  }

  os_profile_windows_config {
    enable_automatic_upgrades = true   # <-- required alongside automatic_os_upgrade
  }
}
```

## Remediation steps
1. Set `automatic_os_upgrade = true` and `upgrade_policy_mode = "Rolling"` (or `"Automatic"`) on the scale set.
2. For Windows scale sets, also set `enable_automatic_upgrades = true` in `os_profile_windows_config`.
3. For newer resources (`azurerm_linux_virtual_machine_scale_set`/`azurerm_windows_virtual_machine_scale_set`), use the `automatic_os_upgrade_policy` block with `disable_automatic_rollback = false` and `enable_automatic_os_upgrade = true`.
4. Ensure your scale set has health probes and a rolling upgrade policy (`max_batch_instance_percent`, `pause_time_between_batches`) configured so automatic upgrades roll out safely without taking down all instances at once.
5. Test the upgrade behavior in a non-production scale set first, since automatic upgrades can introduce unexpected OS-level changes if not paired with adequate health monitoring/rollback settings.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMScaleSetsAutoOSImagePatchingEnabled.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/VMScaleSetsAutoOSImagePatchingEnabled.py
