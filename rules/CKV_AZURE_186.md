# CKV_AZURE_186: Ensure App configuration encryption block is set

## Severity
**MEDIUM** (score: 5.0/10)

Missing customer-managed key encryption for App Configuration reduces control over data-at-rest protection for stored configuration values, which can include sensitive settings, though the store is still protected by Microsoft-managed encryption by default.

## Summary
This check ensures an Azure App Configuration store is configured to use customer-managed key (CMK) encryption via Key Vault, rather than relying solely on Microsoft-managed keys.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (`azurerm` provider)
- **Resource type:** `azurerm_app_configuration`

## Why it matters
By default, Azure App Configuration encrypts data at rest using Microsoft-managed keys, which protects against physical media compromise but gives the customer no control over key lifecycle, rotation policy, or the ability to revoke access to the encryption key independent of Azure. For workloads subject to compliance regimes (e.g., regulatory requirements mandating customer key control, or contractual data-sovereignty obligations), or for defense-in-depth against a compromised Azure-side key, configuring a customer-managed key backed by Key Vault lets the organization control key rotation, access policies, and revocation (e.g., disabling the key immediately renders the encrypted data inaccessible, providing an emergency "kill switch" for the store). Skipping this configuration means the org has no independent control over the encryption key used to protect potentially sensitive configuration data and feature flags.

## How Checkov evaluates this
The check inspects `encryption[0].key_vault_key_identifier` on the `azurerm_app_configuration` resource. It's a positive-value check accepting `ANY_VALUE` — as long as `key_vault_key_identifier` is set to any non-empty value inside an `encryption` block, the check PASSES. If the `encryption` block is absent, or `key_vault_key_identifier` is unset, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_app_configuration" "example" {
  name                = "appconf1"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
  # no encryption block -> Microsoft-managed key only
}
```

## Remediated example
```hcl
resource "azurerm_app_configuration" "example" {
  name                = "appconf1"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"

  identity {
    type = "SystemAssigned"
  }

  encryption {
    key_vault_key_identifier = azurerm_key_vault_key.example.versionless_id
    identity_client_id       = azurerm_user_assigned_identity.example.client_id
  }
}
```

## Remediation steps
1. Create (or identify) a Key Vault key dedicated to encrypting the App Configuration store (`azurerm_key_vault_key`), in a Key Vault with soft-delete and purge protection enabled.
2. Add an `identity` block (system- or user-assigned managed identity) to the `azurerm_app_configuration` resource so it can authenticate to Key Vault.
3. Grant that identity `Get`, `WrapKey`, and `UnwrapKey` permissions on the Key Vault key (via access policy or RBAC role `Key Vault Crypto Service Encryption User`).
4. Add the `encryption` block referencing the key's `versionless_id` (recommended, so automatic key rotation is picked up) as `key_vault_key_identifier`.
5. Requires the `standard` SKU (CMK encryption is not supported on the `free` tier). Enabling CMK on an existing store is applied in place but should be tested in a non-production store first, since losing access to the Key Vault key (e.g. accidental deletion) can render the App Configuration store's data inaccessible.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppConfigEncryption.py
- [Azure App Configuration customer-managed key documentation](https://learn.microsoft.com/en-us/azure/azure-app-configuration/concept-customer-managed-keys)
