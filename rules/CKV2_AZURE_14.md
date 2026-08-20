# CKV2_AZURE_14: Ensure that Unattached disks are encrypted

## Severity
**LOW** (score: 2.0/10)

An unencrypted managed disk can expose all data it contains if the underlying storage is accessed out-of-band, snapshotted, or reattached elsewhere.

## Summary
This check ensures that Azure Managed Disks connected to (or existing independently of) a virtual machine are encrypted, either via a disk encryption set or via encryption settings explicitly enabled.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `azurerm_virtual_machine` and `azurerm_managed_disk`.

## Why it matters
Managed disks — including disks that become "unattached" after a VM is deleted or a disk is detached — can persist sensitive data at rest indefinitely. An unencrypted disk left lying around (e.g. after a VM teardown during infrastructure churn, or a disk provisioned but not yet attached) is a soft target: if Azure RBAC/access controls around the subscription are ever misconfigured or a credential is compromised, an attacker who can attach or export the disk gets plaintext access to whatever was written to it — potentially secrets, PII, or proprietary data from a decommissioned workload. Azure Disk Encryption (via Key Vault-backed disk encryption sets) or platform-managed encryption-at-rest settings close this gap so that even disks not currently in active use remain protected.

## How Checkov evaluates this
Graph check (`AzureUnattachedDisksAreEncrypted.json`), filtered to `azurerm_virtual_machine` resources. PASS if **either**:
1. The VM has **no** connected `azurerm_managed_disk` at all (nothing to check), **or**
2. The VM is connected to a managed disk, and that disk satisfies **either**:
   - it has a `disk_encryption_set_id` attribute set (customer-managed key-based encryption via a Disk Encryption Set), **or**
   - it has an `encryption_settings` block present, and `encryption_settings.enabled` is **not** `false` (i.e., encryption settings exist and aren't explicitly disabled).

FAIL occurs when a connected managed disk has neither a disk encryption set nor enabled encryption settings.

## Non-compliant example
```hcl
resource "azurerm_managed_disk" "data" {
  name                 = "data-disk"
  location             = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  storage_account_type = "Standard_LRS"
  create_option         = "Empty"
  disk_size_gb          = 128
  # No disk_encryption_set_id and no encryption_settings -> fails
}
```

## Remediated example
```hcl
resource "azurerm_disk_encryption_set" "des" {
  name                = "disk-encryption-set"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  key_vault_key_id    = azurerm_key_vault_key.disk_key.id

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_managed_disk" "data" {
  name                 = "data-disk"
  location             = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  storage_account_type = "Standard_LRS"
  create_option         = "Empty"
  disk_size_gb          = 128

  disk_encryption_set_id = azurerm_disk_encryption_set.des.id
}
```

## Remediation steps
1. Prefer a `azurerm_disk_encryption_set` backed by a customer-managed key in Key Vault, and set `disk_encryption_set_id` on every `azurerm_managed_disk`.
2. Note: all Azure managed disks are encrypted at rest by default with platform-managed keys (SSE) since this is an Azure baseline — this check is specifically about whether an *explicit* CMK/encryption-settings configuration is present, useful for organizations requiring visible, auditable encryption configuration rather than implicit platform defaults.
3. Grant the Disk Encryption Set's managed identity `Get`, `WrapKey`, `UnwrapKey` permissions on the Key Vault key, and enable Key Vault soft-delete/purge protection (both required for disk encryption sets).
4. Assigning `disk_encryption_set_id` to an existing disk generally requires the disk to be detached from a running VM first (may require a maintenance window) — check current AzureRM provider/API constraints before applying to production disks.
5. Establish process controls so that disks orphaned by VM deletion are either encrypted before creation or promptly deleted if not needed, minimizing the population of stray unattached disks.
6. Extend equivalent coverage to VM Scale Set-attached disks and newer VM resource types if used, since this specific check's graph only traces `azurerm_virtual_machine` connections.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureUnattachedDisksAreEncrypted.json)
- [Azure: Server-side encryption of Azure Disk Storage](https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption)
