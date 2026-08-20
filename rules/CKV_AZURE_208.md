# CKV_AZURE_208: Ensure that Azure Cognitive Search maintains SLA for index updates

## Severity
**LOW** (score: 2.0/10)

Fewer than 3 replicas is purely an availability/SLA gap for index-update operations, with no direct confidentiality or access-control impact.

## Summary
This check ensures an Azure Cognitive Search service is provisioned with at least 3 replicas, the minimum required by Microsoft to receive an SLA guarantee for index update (write) operations.

## Applicability
- **Frameworks:** Terraform, ARM templates, Bicep
- **Resource types:** `azurerm_search_service` (Terraform), `Microsoft.Search/searchServices` (ARM/Bicep)

## Why it matters
Cognitive Search replicas provide load balancing and high availability across index updates and queries. With fewer than 3 replicas, there is no formal availability guarantee for indexing operations, and — more concretely — a single replica failure or planned maintenance event can leave the service temporarily unable to accept index updates, or with degraded write throughput and no failover redundancy for the write path. For applications relying on near-real-time indexing (e.g. e-commerce catalogs, live content search) this translates directly into stale or unavailable search results during an outage window. This is a reliability/availability control: it ensures the service has enough redundancy that the loss of any single replica does not interrupt the ability to update the index.

## How Checkov evaluates this
**Terraform** — custom `scan_resource_conf`:
- Reads `replica_count`.
- If `replica_count` is set and is an integer, PASSES if `>= 3`, else FAILS.
- If `replica_count` is present but not an integer (e.g. unresolved variable), returns `UNKNOWN`.
- If `replica_count` is absent entirely, FAILS (the provider default is 1 replica, which does not meet the SLA threshold).

**ARM/Bicep** — custom `scan_resource_conf`:
- Reads `properties.replicaCount`.
- PASSES if it's an integer `>= 3`.
- FAILS if `replicaCount` is missing, `properties` isn't a dict, or the count is below 3.

## Non-compliant example
```hcl
resource "azurerm_search_service" "example" {
  name                = "example-search"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
  replica_count       = 1   # below SLA threshold for index updates
}
```

## Remediated example
```hcl
resource "azurerm_search_service" "example" {
  name                = "example-search"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
  replica_count       = 3   # meets SLA threshold
}
```

## Remediation steps
1. Set `replica_count = 3` (or higher) on the `azurerm_search_service` resource, or `properties.replicaCount` in ARM/Bicep.
2. Confirm the chosen SKU supports the desired replica count (the `free` tier does not support multiple replicas; `basic` and above do, up to tier-specific maximums).
3. Increasing replica count adds cost proportionally — evaluate whether the workload's actual availability requirements justify 3+ replicas versus accepting the risk on a lower-tier deployment.
4. This change can be applied to an existing service without downtime; Azure scales replicas in a rolling fashion.
5. Pair with CKV_AZURE_209 (SLA for query operations, minimum 2 replicas) — 3 replicas satisfies both thresholds simultaneously.

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureSearchSLAIndex.py)
- [Checkov ARM check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureSearchSLAIndex.py)
- [Azure Cognitive Search SLA documentation](https://learn.microsoft.com/en-us/azure/search/search-sku-tier)
