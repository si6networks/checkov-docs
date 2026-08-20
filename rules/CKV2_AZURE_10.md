# CKV2_AZURE_10: Ensure that Microsoft Antimalware is configured to automatically updates for Virtual Machines

## Severity
**LOW** (score: 2.0/10)

Without auto-updating antimalware, a VM is more likely to miss signatures for new malware, raising the odds of a successful malware infection going undetected.

## Summary
This check ensures that Azure Virtual Machines have the Microsoft Antimalware (IaaSAntimalware) extension installed with automatic minor-version updates enabled, so the antimalware engine and signature updates stay current without manual intervention.

## Applicability
- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `azurerm_virtual_machine`, connected to an `azurerm_virtual_machine_extension` of type `IaaSAntimalware` published by `Microsoft.Azure.Security`.

## Why it matters
Antimalware software is only as effective as its signature database and engine version. If a VM has the Microsoft Antimalware extension installed but `auto_upgrade_minor_version` is disabled (or the extension is entirely absent), the protection can silently fall behind — missing detection signatures for newly discovered malware families, or running an outdated scan engine with known bypasses. This is particularly risky for internet-facing or otherwise exposed VMs, where malware delivered via a compromised dependency, phishing-downloaded payload, or lateral movement from another compromised host would go undetected by a stale antimalware client. Automatic updates close this gap without requiring manual patch cycles for every VM in the fleet.

## How Checkov evaluates this
Graph check (`AzureAntimalwareIsConfiguredWithAutoUpdatesForVMs.json`). PASS requires **all** of:
1. The `azurerm_virtual_machine` has exactly one connected `azurerm_virtual_machine_extension` (`one_exists`).
2. That extension's `type` attribute equals `"IaaSAntimalware"`.
3. That extension's `publisher` attribute equals `"Microsoft.Azure.Security"`.
4. That extension's `auto_upgrade_minor_version` attribute equals `true`.

If the VM has no such extension, has more than one matching, or the extension exists but `auto_upgrade_minor_version` is not `true` (or publisher/type mismatch), the check fails.

## Non-compliant example
```hcl
resource "azurerm_virtual_machine" "vm" {
  name                  = "app-vm"
  location              = azurerm_resource_group.rg.location
  resource_group_name    = azurerm_resource_group.rg.name
  vm_size                = "Standard_D2s_v3"
  network_interface_ids  = [azurerm_network_interface.nic.id]
  # ... other required VM config omitted for brevity
}

resource "azurerm_virtual_machine_extension" "antimalware" {
  name                 = "IaaSAntimalware"
  virtual_machine_id   = azurerm_virtual_machine.vm.id
  publisher            = "Microsoft.Azure.Security"
  type                 = "IaaSAntimalware"
  type_handler_version = "1.5"

  auto_upgrade_minor_version = false  # not automatically updated
}
```

## Remediated example
```hcl
resource "azurerm_virtual_machine" "vm" {
  name                  = "app-vm"
  location              = azurerm_resource_group.rg.location
  resource_group_name    = azurerm_resource_group.rg.name
  vm_size                = "Standard_D2s_v3"
  network_interface_ids  = [azurerm_network_interface.nic.id]
}

resource "azurerm_virtual_machine_extension" "antimalware" {
  name                 = "IaaSAntimalware"
  virtual_machine_id   = azurerm_virtual_machine.vm.id
  publisher            = "Microsoft.Azure.Security"
  type                 = "IaaSAntimalware"
  type_handler_version = "1.5"

  auto_upgrade_minor_version = true  # enabled

  settings = jsonencode({
    AntimalwareEnabled = true
    RealtimeProtectionEnabled = true
  })
}
```

## Remediation steps
1. Ensure the `azurerm_virtual_machine_extension` for Microsoft Antimalware exists with `publisher = "Microsoft.Azure.Security"` and `type = "IaaSAntimalware"`.
2. Set `auto_upgrade_minor_version = true` on the extension.
3. Confirm only one antimalware extension is attached per VM — duplicates can cause the graph connection check to fail (`one_exists`) and can also conflict at runtime.
4. If migrating to the newer `azurerm_linux_virtual_machine`/`azurerm_windows_virtual_machine` resources, note this check specifically targets the legacy `azurerm_virtual_machine` resource type — verify equivalent coverage exists for VM Scale Sets or the newer VM resource types if used.
5. No VM downtime is required to update extension settings; Azure Extension updates apply without a reboot in most cases, though verify per-extension behavior.
6. Review `settings`/`protectedSettings` for exclusion paths/processes to ensure they aren't overly broad and inadvertently disabling scanning of sensitive directories.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureAntimalwareIsConfiguredWithAutoUpdatesForVMs.json)
- [Azure: Microsoft Antimalware for Azure Cloud Services and Virtual Machines](https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware)
