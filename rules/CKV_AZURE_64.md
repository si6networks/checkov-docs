# CKV_AZURE_64: Ensure that Azure File Sync disables public network access
## Severity
**HIGH** (score: 7.0/10)

Allowing public network access to the Storage Sync Service's control-plane channel unnecessarily exposes an internal file-infrastructure orchestration surface to internet-wide reconnaissance and exploitation attempts.

## Summary
This check fails when an Azure Storage Sync Service does not restrict incoming traffic to virtual networks only, meaning the sync service can be reached over the public internet in addition to (or instead of) private VNet paths.

## Applicability
Applies to Terraform (`azurerm_storage_sync`), ARM templates, and Bicep, for the resource type `Microsoft.StorageSync/storageSyncServices`.

## Why it matters
Azure File Sync coordinates synchronization between on-premises Windows Servers and Azure file shares, and the Storage Sync Service is effectively a management/control-plane channel that can trigger sync operations and access registered server endpoints. If it accepts traffic from the public internet, it expands the exposure surface for an otherwise typically-internal, backend infrastructure component — increasing the risk of unauthorized attempts to interact with sync endpoints, reconnaissance, or exploitation of any future vulnerability in the service's public-facing surface. Restricting `incomingTrafficPolicy` to `AllowVirtualNetworksOnly` ensures the sync service is only reachable from within trusted VNets (e.g. via private endpoint), consistent with the principle that internal orchestration/management services for file infrastructure should not be directly internet-addressable.

## How Checkov evaluates this
- ARM/Bicep: reads `properties/incomingTrafficPolicy` and expects the exact value `"AllowVirtualNetworksOnly"`. If the block/property is missing, the check's `missing_block_result` is FAILED (i.e., no explicit restriction means non-compliant by default).
- Terraform: reads the `incoming_traffic_policy` attribute on `azurerm_storage_sync` and expects `"AllowVirtualNetworksOnly"`; a missing attribute also defaults to FAILED via `missing_block_result`.

## Non-compliant example
```hcl
resource "azurerm_storage_sync" "example" {
  name                = "example-storagesync"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  # incoming_traffic_policy omitted — defaults allow public/all traffic
}
```

## Remediated example
```hcl
resource "azurerm_storage_sync" "example" {
  name                = "example-storagesync"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  incoming_traffic_policy = "AllowVirtualNetworksOnly"  # blocks public network access
}
```

## Remediation steps
1. Set `incoming_traffic_policy = "AllowVirtualNetworksOnly"` (Terraform) or `properties.incomingTrafficPolicy: "AllowVirtualNetworksOnly"` (ARM/Bicep) on the Storage Sync Service.
2. Provision a private endpoint for the Storage Sync Service so registered servers/agents on-premises (via ExpressRoute/VPN) or in-VNet resources can still reach it.
3. Confirm any registered server endpoints and file share sync groups continue to sync correctly after restricting traffic — servers connecting purely over the public internet without a VPN/ExpressRoute path will lose connectivity.
4. Combine with private endpoints on the underlying storage account(s) referenced by the sync groups for full path-of-traffic isolation.
5. Test in a lower environment first if any hybrid on-premises servers depend on public connectivity to the sync service today.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/StorageSyncPublicAccessDisabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageSyncPublicAccessDisabled.py)
- [Azure docs: Azure File Sync networking considerations](https://learn.microsoft.com/en-us/azure/storage/file-sync/file-sync-networking-overview)
