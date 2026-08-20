# CKV2_AZURE_15: Ensure that Azure data factories are encrypted with a customer-managed key

## Severity
**LOW** (score: 2.0/10)

Data Factory is encrypted at rest by default; the absence of a customer-managed key limits key rotation and revocation control rather than leaving pipeline data unencrypted.

## Summary
This check ensures an Azure Data Factory has a customer-managed key configured via a linked Key Vault service, instead of relying solely on Microsoft-managed encryption keys.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `azurerm_data_factory`, connected via `azurerm_data_factory_linked_service_key_vault`.

## Why it matters
Azure Data Factory orchestrates and stores pipeline metadata, linked service connection strings/credentials, and staged datasets that can include sensitive configuration and business data. Without a customer-managed key, all of this is protected only by Microsoft-managed keys, meaning the organization has no independent ability to revoke encryption access, no control over key rotation cadence, and cannot meet compliance frameworks that require demonstrable, exclusive customer control over the keys protecting sensitive data. In the event of a legal hold, incident response action, or offboarding scenario, being able to instantly disable a customer-managed key (cutting off decryption capability) is a control that simply doesn't exist with platform-managed keys.

## How Checkov evaluates this
Graph check (`AzureDataFactoriesEncryptedWithCustomerManagedKey.json`). PASS requires:
1. Filter to `azurerm_data_factory` resources.
2. The Data Factory must have a **connection** to an `azurerm_data_factory_linked_service_key_vault` resource.

FAIL if no such linked Key Vault service connection exists.

## Non-compliant example
```hcl
resource "azurerm_data_factory" "adf" {
  name                = "app-data-factory"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}
# No azurerm_data_factory_linked_service_key_vault -> fails
```

## Remediated example
```hcl
resource "azurerm_data_factory" "adf" {
  name                = "app-data-factory"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_data_factory_linked_service_key_vault" "kv_link" {
  name            = "adf-key-vault-link"
  data_factory_id = azurerm_data_factory.adf.id
  key_vault_id    = azurerm_key_vault.kv.id
}

resource "azurerm_data_factory_customer_managed_key" "adf_cmk" {
  data_factory_id     = azurerm_data_factory.adf.id
  key_vault_key_id    = azurerm_key_vault_key.adf_key.versionless_id
  key_vault_id        = azurerm_data_factory_linked_service_key_vault.kv_link.id
}
```

## Remediation steps
1. Enable a `SystemAssigned` (or `UserAssigned`) managed identity on the Data Factory.
2. Create an `azurerm_data_factory_linked_service_key_vault` resource linking the factory to the Key Vault containing your encryption key.
3. Grant the Data Factory's identity `Get`, `WrapKey`, and `UnwrapKey` permissions on the target key.
4. Configure `azurerm_data_factory_customer_managed_key` referencing the linked service and the specific key (note: Azure requires the key reference to be "versionless" for CMK auto-rotation support).
5. Enabling CMK on an existing Data Factory can have provider/API-version-specific ordering requirements (linked service must exist before the CMK resource) — apply in stages if Terraform reports dependency errors.
6. Ensure Key Vault has soft-delete and purge protection enabled — required for Data Factory CMK integration — and monitor key expiration/rotation to avoid factory outages from an inaccessible key.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureDataFactoriesEncryptedWithCustomerManagedKey.json)
- [Azure Data Factory: Encrypt Data Factory with customer-managed keys](https://learn.microsoft.com/en-us/azure/data-factory/enable-customer-managed-key)
