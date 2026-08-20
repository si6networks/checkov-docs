# CKV2_AZURE_35: Ensure Azure recovery services vault is configured with managed identity
## Severity
**LOW** (score: 2.0/10)

Without a managed identity, the Recovery Services vault must rely on stored credentials or broader shared secrets to interact with backup targets, increasing credential exposure risk versus scoped, rotation-free identity-based access.

## Summary
This check verifies that an Azure Recovery Services Vault (used for Azure Backup and Site Recovery) has a managed identity configured, rather than relying on other credential mechanisms for its automation and cross-resource operations.

## Applicability
- **IaC framework:** Terraform (graph-based attribute check)
- **Resource type involved:** `azurerm_recovery_services_vault`

## Why it matters
Recovery Services Vaults orchestrate backup and disaster-recovery operations that require permissions to read and write across potentially many resources (VMs, disks, databases, storage accounts holding backup data). Without a managed identity, granting the vault the permissions it needs to perform cross-resource operations (e.g., encrypting backups with a customer-managed key in Key Vault, or cross-region restore operations) typically falls back to less secure mechanisms or requires broader, less auditable permission grants elsewhere. A managed identity lets Azure AD authenticate the vault's automated operations directly, with permissions scoped and revocable via RBAC, and without any embedded credential existing at all — closing off both credential-leakage risk and the temptation to over-grant static service principal permissions.

## How Checkov evaluates this
This is a **graph-based attribute check** with two ANDed conditions:
1. `identity.type` must `exist` on the `azurerm_recovery_services_vault` resource.
2. `identity.type` must have a non-zero "number of words" (i.e., not an empty string).

If the `identity` block is absent, or present with an empty `type`, the resource FAILS.

## Non-compliant example
```hcl
resource "azurerm_recovery_services_vault" "example" {
  name                = "example-recovery-vault"
  location            = "eastus"
  resource_group_name = "example-rg"
  sku                 = "Standard"

  soft_delete_enabled = true

  # No identity block configured.
}
```

## Remediated example
```hcl
resource "azurerm_recovery_services_vault" "example" {
  name                = "example-recovery-vault"
  location            = "eastus"
  resource_group_name = "example-rg"
  sku                 = "Standard"

  soft_delete_enabled = true

  # Added: system-assigned managed identity.
  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Add an `identity` block to the `azurerm_recovery_services_vault` resource, typically with `type = "SystemAssigned"` (or `"UserAssigned"`/`"SystemAssigned, UserAssigned"` as needed).
2. Grant the resulting identity the least-privilege RBAC roles it needs — for example, `Key Vault Crypto Service Encryption User` if using customer-managed key encryption for backups, or appropriate roles on target resources for cross-region restore scenarios.
3. If enabling customer-managed key encryption for the vault, the managed identity must be configured before the CMK encryption settings are applied.
4. Verify no existing automation depends on a different (e.g., service principal-based) authentication path for vault operations before switching over.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureRecoveryServicesvaultConfigManagedIdentity.json)
- [Managed identities for Azure Backup](https://learn.microsoft.com/en-us/azure/backup/encryption-at-rest-with-cmk)
