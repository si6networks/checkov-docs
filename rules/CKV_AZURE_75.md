# CKV_AZURE_75: Ensure that Azure Data Explorer uses double encryption

## Severity
**LOW** (score: 2.0/10)

Missing double (infrastructure-level) encryption is a defense-in-depth gap on top of already-encrypted-at-rest data, reducing resilience against a single-layer key compromise rather than leaving data fully unprotected.

## Summary
This check ensures Azure Data Explorer (Kusto) clusters have double encryption enabled, layering a second, infrastructure-level encryption on top of standard storage-service encryption.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_kusto_cluster`
- **ARM/Bicep**: `Microsoft.Kusto/clusters`

## Why it matters
Standard Azure Storage Service Encryption protects data at rest with a single encryption layer. Double encryption adds a second layer at the infrastructure level using a different encryption algorithm/key, so that a compromise or flaw in one encryption layer (e.g. a cryptographic weakness discovered in the future, or a key-management failure at one layer) does not by itself expose the underlying data. This is particularly relevant for regulated workloads (financial, healthcare, government) where compliance frameworks mandate defense-in-depth for data at rest. Without it, a Kusto cluster relies on a single point of encryption failure to protect ingested data.

## How Checkov evaluates this
`BaseResourceValueCheck` inspects `double_encryption_enabled` (Terraform) or `properties/enableDoubleEncryption` (ARM) and expects `true`. Missing or `false` values fail the check.

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
  # double_encryption_enabled omitted -> single layer of encryption only
}
```

## Remediated example
```hcl
resource "azurerm_kusto_cluster" "example" {
  name                       = "examplekustocluster"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  double_encryption_enabled  = true   # adds a second, independent encryption layer

  sku {
    name     = "Standard_D13_v2"
    capacity = 2
  }
}
```

## Remediation steps
1. Set `double_encryption_enabled = true` on the `azurerm_kusto_cluster` resource.
2. This setting is generally immutable after cluster creation — enabling it on an existing cluster typically requires destroying and recreating the cluster, so plan for a migration window and re-ingestion of data if changing an existing environment.
3. Confirm the target region/SKU supports double encryption before rollout, as availability can vary.
4. Pair with `disk_encryption_enabled` (CKV_AZURE_74) for full at-rest protection of both cache and persistent layers.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDataExplorerDoubleEncryptionEnabled.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureDataExplorerDoubleEncryptionEnabled.py
- Azure docs: https://learn.microsoft.com/en-us/azure/data-explorer/security
