# CKV2_AZURE_12: Ensure that virtual machines are backed up using Azure Backup

## Severity
**LOW** (score: 2.0/10)

An unbacked-up VM risks unrecoverable data loss following ransomware, corruption, or accidental deletion, an availability rather than confidentiality impact.

## Summary
This check ensures that Azure Virtual Machines are enrolled in Azure Backup by verifying a connection to an `azurerm_backup_protected_vm` resource.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `azurerm_virtual_machine`, connected via `azurerm_backup_protected_vm`.

## Why it matters
A VM with no Azure Backup protection has no managed recovery point if the OS/data disk is corrupted, a deployment goes wrong, ransomware encrypts the disk, or the VM is accidentally deleted. Azure Backup provides application-consistent (or crash-consistent) recovery points on a schedule, stored in a Recovery Services vault that is logically and often geographically separate from the VM itself — protecting against both operational mistakes and account-level compromise. Without it, recovery depends entirely on ad hoc snapshots or, worse, nothing at all, turning what should be a routine restore into a potential unrecoverable data-loss incident.

## How Checkov evaluates this
Graph check (`VMHasBackUpMachine.json`). PASS requires:
1. Filter to `azurerm_virtual_machine` resources.
2. The VM must have a **connection** to an `azurerm_backup_protected_vm` resource (which associates the VM with a Recovery Services vault backup policy).

FAIL if no such connection exists — i.e., the VM is not registered with any backup protection resource.

## Non-compliant example
```hcl
resource "azurerm_virtual_machine" "vm" {
  name                = "app-vm"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  vm_size             = "Standard_D2s_v3"
  network_interface_ids = [azurerm_network_interface.nic.id]
}
# No azurerm_backup_protected_vm referencing this VM -> fails
```

## Remediated example
```hcl
resource "azurerm_virtual_machine" "vm" {
  name                = "app-vm"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  vm_size             = "Standard_D2s_v3"
  network_interface_ids = [azurerm_network_interface.nic.id]
}

resource "azurerm_recovery_services_vault" "vault" {
  name                = "vm-backup-vault"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Standard"
  soft_delete_enabled = true
}

resource "azurerm_backup_policy_vm" "daily" {
  name                = "daily-vm-backup-policy"
  resource_group_name = azurerm_resource_group.rg.name
  recovery_vault_name = azurerm_recovery_services_vault.vault.name

  backup {
    frequency = "Daily"
    time      = "23:00"
  }

  retention_daily {
    count = 14
  }
}

resource "azurerm_backup_protected_vm" "vm_backup" {
  resource_group_name = azurerm_resource_group.rg.name
  recovery_vault_name = azurerm_recovery_services_vault.vault.name
  source_vm_id        = azurerm_virtual_machine.vm.id
  backup_policy_id    = azurerm_backup_policy_vm.daily.id
}
```

## Remediation steps
1. Create (or reuse) an `azurerm_recovery_services_vault` in the same or a paired region as the VM.
2. Define an `azurerm_backup_policy_vm` with a schedule and retention matching your RPO/RTO requirements.
3. Add an `azurerm_backup_protected_vm` resource linking the VM's `id` (as `source_vm_id`) to the vault and policy.
4. This is additive infrastructure — no VM downtime or replacement is required, though the first backup job can take time to complete depending on disk size.
5. Ensure the Recovery Services vault has soft-delete enabled to protect against accidental/malicious backup deletion.
6. If VMs are managed via `azurerm_linux_virtual_machine`/`azurerm_windows_virtual_machine` instead of the legacy `azurerm_virtual_machine`, confirm this specific check's coverage (it targets `azurerm_virtual_machine`) and verify equivalent backup protection is still applied to those resource types.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/VMHasBackUpMachine.json)
- [Azure Backup: Back up an Azure VM](https://learn.microsoft.com/en-us/azure/backup/backup-azure-arm-vms-prepare)
