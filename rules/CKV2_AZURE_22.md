# CKV2_AZURE_22: Ensure that Cognitive Services enables customer-managed key for encryption
## Severity
**LOW** (score: 2.0/10)

Relying on platform-managed keys instead of a customer-managed key for Cognitive Services reduces control over key lifecycle and revocation for potentially sensitive AI workload data, but data is still encrypted at rest by default.

## Summary
This check verifies that an Azure Cognitive Services account is linked to a customer-managed key (CMK) resource, which in turn is linked to a Key Vault key, rather than relying solely on Microsoft-managed encryption keys.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check)
- **Resource types involved:** `azurerm_cognitive_account`, `azurerm_cognitive_account_customer_managed_key`, `azurerm_key_vault_key`

## Why it matters
By default, data at rest in Azure Cognitive Services is encrypted with Microsoft-managed keys, which Microsoft fully controls the lifecycle of. Organizations subject to regulatory or contractual requirements (financial services, healthcare, government) often need to control and rotate the encryption keys themselves, and to be able to instantly revoke access to the underlying data by disabling or deleting the key — something impossible with platform-managed keys. Without a customer-managed key, the organization cannot demonstrate cryptographic control over its data, cannot enforce key rotation policy, and loses the ability to immediately "crypto-shred" data by revoking key access (e.g., during an offboarding, tenant separation, or incident-response scenario).

## How Checkov evaluates this
This is a **graph-based** check evaluating a connection chain:
1. The `azurerm_cognitive_account` must have a graph connection to an `azurerm_cognitive_account_customer_managed_key` resource.
2. That CMK resource must in turn have a graph connection to an `azurerm_key_vault_key` resource.
3. The result is filtered to report PASS/FAIL on the `azurerm_cognitive_account` resource.

If a Cognitive Services account has no linked `azurerm_cognitive_account_customer_managed_key` resource (or that resource isn't wired to an actual Key Vault key), the account FAILS the check.

## Non-compliant example
```hcl
resource "azurerm_cognitive_account" "example" {
  name                = "example-cognitive-account"
  location            = "eastus"
  resource_group_name = "example-rg"
  kind                = "TextAnalytics"
  sku_name            = "S0"
}

# No azurerm_cognitive_account_customer_managed_key resource defined —
# encryption relies on Microsoft-managed keys only.
```

## Remediated example
```hcl
resource "azurerm_key_vault" "example" {
  name                = "example-kv"
  location            = "eastus"
  resource_group_name = "example-rg"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  purge_protection_enabled = true
}

resource "azurerm_key_vault_key" "example" {
  name         = "cognitive-cmk"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}

resource "azurerm_cognitive_account" "example" {
  name                = "example-cognitive-account"
  location            = "eastus"
  resource_group_name = "example-rg"
  kind                = "TextAnalytics"
  sku_name            = "S0"

  identity {
    type = "SystemAssigned"
  }
}

# Added: customer-managed key resource wiring the account to the Key Vault key.
resource "azurerm_cognitive_account_customer_managed_key" "example" {
  cognitive_account_id = azurerm_cognitive_account.example.id
  key_vault_key_id     = azurerm_key_vault_key.example.id
}
```

## Remediation steps
1. Create (or identify) a Key Vault and an `azurerm_key_vault_key` to serve as the CMK.
2. Enable a system- or user-assigned managed identity on the `azurerm_cognitive_account` and grant it Key Vault access (via access policy or Azure RBAC — `Key Vault Crypto Service Encryption User` or equivalent).
3. Add an `azurerm_cognitive_account_customer_managed_key` resource linking the Cognitive Services account to the key.
4. Ensure the Key Vault has purge protection and soft-delete enabled, since CMK-encrypted resources become inaccessible if the key vault/key is deleted.
5. Plan for key rotation procedures — rotating the underlying key material should not require redeploying the Cognitive Services account itself if `key_vault_key_id` is updated correctly.
6. Note: not all Cognitive Services `kind` values support CMK — verify your specific service kind (e.g., certain kinds require dedicated/commitment-tier SKUs) supports customer-managed keys before depending on this configuration.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/CognitiveServicesCustomerManagedKey.json)
- [Azure Cognitive Services encryption of data at rest](https://learn.microsoft.com/en-us/azure/ai-services/encryption/cognitive-services-encryption-keys-portal)
