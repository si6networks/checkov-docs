# CKV_AZURE_74: Ensure that Azure Data Explorer (Kusto) uses disk encryption

## Severity
**LOW** (score: 2.0/10)

Disabled disk encryption on Data Explorer clusters leaves data at rest in cleartext, exposing sensitive analytics data if underlying storage media or backups are compromised.

## Summary
This check ensures Azure Data Explorer (Kusto) clusters have disk encryption enabled for their local/cache disks.

## Applicability
- **Terraform**: `azurerm_kusto_cluster`
- **ARM/Bicep**: `Microsoft.Kusto/clusters`

## Why it matters
Kusto clusters cache ingested data on local SSDs attached to the cluster nodes for fast query performance, in addition to storing data in the backing storage account. If disk encryption is disabled, that locally-cached data sits unencrypted on the underlying disk. Should the underlying physical media be improperly decommissioned, accessed outside Azure's normal control plane, or exposed through a platform-level vulnerability, the cached data — which can include ingested log data, telemetry, or business data — is readable without needing the customer's encryption keys. Enabling disk encryption ensures the cache layer benefits from the same at-rest protection expected of the persistent storage layer.

## How Checkov evaluates this
`BaseResourceValueCheck` inspects `disk_encryption_enabled` (Terraform) or `properties/enableDiskEncryption` (ARM) and expects it to be `true`. The resource fails if the attribute is missing or `false`.

## Non-compliant example
```hcl
resource "azurerm_kusto_cluster" "example" {
  name                = "examplekustocluster"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku {
    name     = "Standard_D13_v2"
    capacity = 2
  }
  # disk_encryption_enabled omitted -> defaults to false
}
```

## Remediated example
```hcl
resource "azurerm_kusto_cluster" "example" {
  name                     = "examplekustocluster"
  location                 = azurerm_resource_group.example.location
  resource_group_name      = azurerm_resource_group.example.name
  disk_encryption_enabled  = true   # encrypts local cache disks

  sku {
    name     = "Standard_D13_v2"
    capacity = 2
  }
}
```

## Remediation steps
1. Set `disk_encryption_enabled = true` on the `azurerm_kusto_cluster` resource (`properties.enableDiskEncryption: true` in ARM/Bicep).
2. Verify this setting can be changed on an existing cluster in your target region/SKU — some legacy SKUs may require cluster recreation to apply disk encryption.
3. Combine with double encryption (CKV_AZURE_75) for defense-in-depth if data sensitivity warrants it.
4. Test cluster performance after enabling encryption, as encryption can introduce a small overhead on local disk I/O.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataExplorerUsesDiskEncryption.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/DataExplorerUsesDiskEncryption.py
- Azure docs: https://learn.microsoft.com/en-us/azure/data-explorer/security
