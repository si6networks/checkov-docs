# CKV_AZURE_250: Ensure Storage Sync Service is not configured with overly permissive network access

## Severity
**HIGH** (score: 7.5/10)

Setting Storage Sync Service to allow all incoming traffic removes network-level access restriction on a service that manages file server data replication, exposing it broadly instead of to trusted networks only.

## Summary
This check ensures that an Azure File Sync `azurerm_storage_sync` resource does not allow all incoming traffic; its `incoming_traffic_policy` must be set to a restricted value rather than `AllowAllTraffic`.

## Applicability
- **Framework:** Terraform
- **Resource type:** `azurerm_storage_sync`

## Why it matters
Azure File Sync's Storage Sync Service coordinates file synchronization between on-premises servers and Azure File shares, and its endpoint can carry sensitive file-share metadata and sync traffic. When `incoming_traffic_policy` is set to `AllowAllTraffic` (or left unset, which the check also treats as non-compliant), the service accepts connections from any network path rather than being restricted to selected private endpoints or trusted networks. This widens the attack surface for the sync endpoint, allowing potential unauthorized registration of new sync server endpoints or interception/tampering attempts on management traffic. Restricting incoming traffic (e.g., to `AllowVirtualNetworksOnly` or a private-endpoint-only configuration) ensures only trusted network paths can reach the sync service.

## How Checkov evaluates this
This is a `BaseResourceCheck`:
- **FAIL** if `incoming_traffic_policy` is missing entirely from the resource configuration.
- **FAIL** if `incoming_traffic_policy` is set to `"AllowAllTraffic"`.
- **PASS** for any other explicitly-set restrictive value.

## Non-compliant example
```hcl
resource "azurerm_storage_sync" "example" {
  name                = "example-storagesync"
  resource_group_name = azurerm_resource_group.example.name
  location            = "eastus"

  incoming_traffic_policy = "AllowAllTraffic"
}
```

## Remediated example
```hcl
resource "azurerm_storage_sync" "example" {
  name                = "example-storagesync"
  resource_group_name = azurerm_resource_group.example.name
  location            = "eastus"

  incoming_traffic_policy = "AllowVirtualNetworksOnly"  # was "AllowAllTraffic"
}
```

## Remediation steps
1. Set `incoming_traffic_policy` explicitly (never leave it unset) to a restrictive value such as `AllowVirtualNetworksOnly`.
2. Pair this with a private endpoint on the Storage Sync Service so management and sync traffic stays on the private network path.
3. Update any on-premises registered servers' network configuration/firewall rules to match the new restricted traffic policy before rolling this out, to avoid breaking existing sync jobs.
4. Confirm the `azurerm` provider version in use supports the `incoming_traffic_policy` argument.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageSyncServicePermissiveAccess.py)
- [Azure File Sync networking guidance](https://learn.microsoft.com/en-us/azure/storage/file-sync/file-sync-networking-overview)
