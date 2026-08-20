# CKV_AZURE_3: Ensure that 'supportsHttpsTrafficOnly' is set to 'true'

## Severity
**LOW** (score: 2.0/10)

Allowing plain HTTP to a storage account exposes SAS tokens, account keys, and blob/file/queue/table content to interception or tampering by anyone on the network path.

## Summary
This check ensures Azure Storage Accounts require HTTPS for all data-plane traffic (blobs, files, tables, queues) rather than allowing plaintext HTTP connections.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, Bicep, ARM
- **Resource types:** `Microsoft.Storage/storageAccounts`, `azurerm_storage_account`

## Why it matters
When `supportsHttpsTrafficOnly` (Terraform: `enable_https_traffic_only`) is disabled, the storage account will accept connections over plain HTTP in addition to HTTPS. Any client, proxy, or network device on the path between the caller and Azure Storage can then read or tamper with data in transit — including shared access signature (SAS) tokens, storage account keys sent in `Authorization` headers, and the actual blob/file/queue/table content — since none of it is encrypted. This is a straightforward network eavesdropping/MITM exposure, and since storage accounts frequently hold application secrets, backups, and user-uploaded content, an HTTP-accessible endpoint significantly expands the practical attack surface for credential and data theft.

## How Checkov evaluates this
**ARM check**: reads `properties.supportsHttpsTrafficOnly`. **PASS** if it equals `"true"` (case-insensitive string compare); **FAIL** otherwise. If the attribute is absent, it falls back to the resource's `apiVersion`: API versions from 2019 onward default to `true` (**PASS**); versions before 2019 default to `false` (**FAIL**); if the API version can't be parsed, returns **UNKNOWN**.

**Bicep check**: same idea — reads `properties.supportsHttpsTrafficOnly` as a boolean; falls back to the template's `apiVersion` year if unset, with the same pre/post-2019 default logic.

**Terraform check** (`BaseResourceValueCheck`): inspects `enable_https_traffic_only` on `azurerm_storage_account`, expecting it to be `true`. (Note the Terraform provider attribute name differs from the ARM property name, though both control the same underlying setting.)

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  enable_https_traffic_only = false
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  enable_https_traffic_only = true   # was false
}
```

## Remediation steps
1. Set `enable_https_traffic_only = true` in Terraform (in newer `azurerm` provider versions this argument may be renamed `https_traffic_only_enabled` — check your provider version's changelog).
2. In ARM/Bicep, set `properties.supportsHttpsTrafficOnly` to `true` explicitly rather than relying on the API-version default.
3. Audit any legacy clients/scripts using `http://` endpoints against the storage account and migrate them to `https://` before enforcing this, or they will start failing.
4. This setting does not require resource replacement and can typically be applied to existing storage accounts with no downtime, aside from breaking any genuinely HTTP-only clients.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountsTransportEncryption.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/StorageAccountsTransportEncryption.py)
- [Checkov check source (Bicep)](https://github.com/bridgecrewio/checkov/blob/main/checkov/bicep/checks/resource/azure/StorageAccountsTransportEncryption.py)
- [Azure Storage: require secure transfer](https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer)
