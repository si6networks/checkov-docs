# CKV_AZURE_187: Ensure App configuration purge protection is enabled

## Severity
**MEDIUM** (score: 5.0/10)

Without purge protection, a deleted App Configuration store (and any sensitive settings it held) can be permanently and irrecoverably purged, which is primarily a data-recovery/availability concern rather than a direct confidentiality exposure.

## Summary
This check ensures Azure App Configuration stores have purge protection enabled, preventing permanent, immediate deletion of a soft-deleted store.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (`azurerm` provider)
- **Resource type:** `azurerm_app_configuration`

## Why it matters
Azure App Configuration supports a soft-delete mechanism: a deleted store is retained for a recovery period rather than removed immediately. However, without purge protection, anyone with sufficient permissions can permanently purge a soft-deleted store immediately, bypassing the recovery window entirely. This matters both as a defense against accidental data loss (e.g. a mistaken `terraform destroy` or a scripting error deleting and then purging a store) and as a defense against malicious insiders or a compromised account attempting to destroy configuration data (including feature flags or settings that other critical services depend on) without a chance for recovery. Purge protection enforces that even an intentional delete leaves a recoverable window, giving operations teams a chance to restore before data is unrecoverably lost.

## How Checkov evaluates this
The check is a positive-value check on `purge_protection_enabled` with `missing_block_result=FAILED`. This means: if the attribute is entirely absent from the resource configuration, the check FAILS (fail closed). The check's base class (`BaseResourceValueCheck`) expects the value to equal the class default (`True`, since no `get_expected_value` override is provided, so it defaults to expecting a truthy value) — so `purge_protection_enabled = true` PASSES, and `purge_protection_enabled = false` (or the attribute being absent) FAILS.

## Non-compliant example
```hcl
resource "azurerm_app_configuration" "example" {
  name                       = "appconf1"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  sku                        = "standard"
  purge_protection_enabled   = false
}
```

## Remediated example
```hcl
resource "azurerm_app_configuration" "example" {
  name                       = "appconf1"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  sku                        = "standard"
  purge_protection_enabled   = true
}
```

## Remediation steps
1. Set `purge_protection_enabled = true` explicitly on every `azurerm_app_configuration` resource.
2. Be aware this setting is **immutable once enabled** — you cannot disable purge protection on an existing store afterward, and Terraform will attempt a resource replacement (destroy/recreate) if you try to flip it back to `false`, which is destructive. Set it deliberately and confirm the org's intent before applying.
3. Combine with the store's default soft-delete retention period (currently fixed at 7 days by Azure) to ensure adequate recovery time.
4. Requires the `standard` SKU for App Configuration (purge protection is not available on `free`).
5. Ensure IAM/RBAC on the resource group and subscription restricts who can delete App Configuration stores at all, since purge protection only guards against *purging* a soft-deleted store, not the initial delete.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppConfigPurgeProtection.py
- [Azure App Configuration soft delete/purge protection documentation](https://learn.microsoft.com/en-us/azure/azure-app-configuration/concept-soft-delete)
