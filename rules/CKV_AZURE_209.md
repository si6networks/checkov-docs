# CKV_AZURE_209: Ensure that Azure Cognitive Search maintains SLA for search index queries

## Severity
**LOW** (score: 2.0/10)

Fewer than 2 replicas is purely an availability/SLA gap for query serving, with no direct confidentiality or access-control impact.

## Summary
This check ensures an Azure Cognitive Search service is provisioned with at least 2 replicas, the minimum required by Microsoft to receive an SLA guarantee for search query (read) operations.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, ARM templates, Bicep
- **Resource types:** `azurerm_search_service` (Terraform), `Microsoft.Search/searchServices` (ARM/Bicep)

## Why it matters
Search queries are typically the most latency- and availability-sensitive part of a search-backed application — end users experience query failures directly (broken search boxes, empty results, degraded UX). With only a single replica, any node-level failure, restart, or maintenance event removes the service's ability to serve queries entirely, since there is no redundant replica to fail over to. Two or more replicas allow queries to be load-balanced and to continue being served if one replica becomes temporarily unavailable, which is the baseline Microsoft requires before it will offer an SLA for query availability. Applications with high uptime requirements for search-driven features (product catalogs, internal knowledge bases used during incident response, customer support tooling) should treat this as a minimum, not merely a compliance checkbox.

## How Checkov evaluates this
**Terraform** — custom `scan_resource_conf`:
- Reads `replica_count`.
- PASSES if it is an integer `>= 2`.
- Returns `UNKNOWN` if `replica_count` is present but not a resolvable integer.
- FAILS if `replica_count` is absent or below 2 (the provider default of 1 replica does not satisfy this).

**ARM/Bicep** — custom `scan_resource_conf`:
- Reads `properties.replicaCount`.
- PASSES if it's an integer `>= 2`.
- Returns `UNKNOWN` if present but non-integer.
- FAILS if `properties` isn't a dict or `replicaCount` is absent/below 2.

## Non-compliant example
```hcl
resource "azurerm_search_service" "example" {
  name                = "example-search"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
  replica_count       = 1   # no query-availability redundancy
}
```

## Remediated example
```hcl
resource "azurerm_search_service" "example" {
  name                = "example-search"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
  replica_count       = 2   # meets minimum for query SLA
}
```

## Remediation steps
1. Set `replica_count = 2` (or higher — 3 to also satisfy the index-update SLA in CKV_AZURE_208) on the resource.
2. Verify the SKU tier supports multiple replicas (the `free` tier is limited to 1 replica and cannot pass this check).
3. Consider going straight to 3 replicas if the workload also performs frequent index updates, satisfying both this check and CKV_AZURE_208 in one change.
4. This is a scaling operation that can be performed on a running service without downtime.
5. Monitor query latency/throughput post-change to right-size replica count against actual load rather than over-provisioning.

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureSearchSLAQueryUpdates.py)
- [Checkov ARM check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureSearchSLAQueryUpdates.py)
- [Azure Cognitive Search SLA documentation](https://learn.microsoft.com/en-us/azure/search/search-sku-tier)
