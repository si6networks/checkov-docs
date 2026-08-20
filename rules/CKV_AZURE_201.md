# CKV_AZURE_201: Ensure that Azure Service Bus uses a customer-managed key to encrypt data

## Severity
**MEDIUM** (score: 5.0/10)

Without a customer-managed key, Service Bus data is still encrypted by default (with Microsoft-managed keys), but the organization loses independent key rotation/revocation control, which matters most as a compliance and incident-containment gap rather than an immediate exposure.

## Summary
This check ensures an Azure Service Bus namespace is configured with a customer-managed key (CMK) reference for encryption, rather than relying solely on Microsoft-managed keys.

## Applicability
- **Framework:** Terraform
- **Resource type:** `azurerm_servicebus_namespace`

## Why it matters
By default, Service Bus encrypts data at rest with Microsoft-managed keys, which Microsoft fully controls (creation, rotation, access). Using a customer-managed key stored in Azure Key Vault gives the organization direct control over the encryption key's lifecycle — the ability to rotate it on its own schedule, revoke access instantly (e.g. during an incident, by disabling the key or its access policy), and enforce separation of duties between the data plane and key management. Without CMK, an organization cannot independently revoke Microsoft's ability to decrypt the data, and cannot satisfy compliance regimes that mandate customer control over key material (common in finance, healthcare, and government contracts). If the underlying storage or a Microsoft-managed key were ever compromised, there's no customer-side lever to cut off access quickly.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `customer_managed_key/[0]/key_vault_key_id`
- **Expected value:** `ANY_VALUE` — any non-empty value for `key_vault_key_id` satisfies the check.
- The check FAILS if the `customer_managed_key` block is absent, or present without a `key_vault_key_id`.

## Non-compliant example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Premium"
  # no customer_managed_key block - relies on Microsoft-managed keys only
}
```

## Remediated example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Premium"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.example.id]
  }

  customer_managed_key {
    key_vault_key_id = azurerm_key_vault_key.example.id   # CMK reference
    identity_id      = azurerm_user_assigned_identity.example.id
  }
}
```

## Remediation steps
1. Ensure the namespace SKU is `Premium` — CMK support requires Premium tier.
2. Create (or reference) a Key Vault key dedicated to Service Bus encryption, in a vault with soft-delete and purge protection enabled.
3. Assign a user-assigned managed identity to the namespace (or use system-assigned) and grant it `Get`, `WrapKey`, `UnwrapKey` permissions on the Key Vault key.
4. Add a `customer_managed_key` block referencing `key_vault_key_id` and the identity.
5. Note: converting an existing namespace to CMK, and CMK key rotation, may have operational implications — test in a non-production namespace first, and monitor for encryption-related throttling or errors after the change.
6. Combine with CKV_AZURE_202 (managed identity enabled) and CKV_AZURE_199 (double encryption), both of which build on this CMK configuration.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusHasCMK.py)
- [Azure Service Bus customer-managed key documentation](https://learn.microsoft.com/en-us/azure/service-bus-messaging/configure-customer-managed-key)
