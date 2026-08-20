# CKV_AZURE_199: Ensure that Azure Service Bus uses double encryption

## Severity
**MEDIUM** (score: 5.0/10)

This check only governs an additional infrastructure-level encryption layer on top of Service Bus's always-on default encryption, so its absence is a defense-in-depth gap rather than a path to unencrypted data.

## Summary
This check ensures an Azure Service Bus namespace has infrastructure-level (double) encryption enabled on top of the standard service-side encryption, when using customer-managed keys.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `azurerm_servicebus_namespace`

## Why it matters
Azure Service Bus already encrypts data at rest by default using Microsoft-managed keys. "Double encryption" (infrastructure encryption) adds a second layer of encryption at the infrastructure level, using a different encryption algorithm/key than the default service encryption. This defense-in-depth approach protects data even in the unlikely event that one encryption layer or its key material is compromised — a single algorithm flaw, key-management bug, or implementation vulnerability in one layer does not by itself expose plaintext data. This is particularly relevant for regulated workloads (financial services, healthcare, government) that mandate multiple independent layers of at-rest protection as part of compliance frameworks (e.g. FedRAMP, PCI-DSS enhanced requirements).

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `customer_managed_key/[0]/infrastructure_encryption_enabled`
- **Expected value:** `True`
- The check FAILS unless the namespace defines a `customer_managed_key` block with `infrastructure_encryption_enabled = true`. Since this attribute is nested inside `customer_managed_key`, double encryption in Checkov's model is only satisfiable when a customer-managed key configuration is present (Service Bus double encryption requires CMK — it is not available with Microsoft-managed keys).

## Non-compliant example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Premium"

  customer_managed_key {
    key_vault_key_id                  = azurerm_key_vault_key.example.id
    identity_id                       = azurerm_user_assigned_identity.example.id
    # infrastructure_encryption_enabled not set (defaults to false)
  }
}
```

## Remediated example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Premium"

  customer_managed_key {
    key_vault_key_id                    = azurerm_key_vault_key.example.id
    identity_id                         = azurerm_user_assigned_identity.example.id
    infrastructure_encryption_enabled   = true   # enables double encryption
  }
}
```

## Remediation steps
1. Ensure the Service Bus namespace uses the `Premium` SKU — customer-managed keys (and therefore double encryption) require Premium tier.
2. Add a `customer_managed_key` block referencing a Key Vault key and an identity with access to it (see CKV_AZURE_201).
3. Set `infrastructure_encryption_enabled = true` within that block.
4. Note: `infrastructure_encryption_enabled` can only be set at namespace creation time in Azure — enabling it on an existing namespace typically requires recreating the namespace, so plan for a migration window if this attribute needs to change on a live resource.
5. Confirm the associated Key Vault has purge protection and soft delete enabled, since losing the CMK key makes data permanently inaccessible.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusDoubleEncryptionEnabled.py)
- [Azure Service Bus encryption at rest documentation](https://learn.microsoft.com/en-us/azure/service-bus-messaging/configure-customer-managed-key)
