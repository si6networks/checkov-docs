# CKV_AZURE_228: Ensure the Azure Event Hub Namespace is zone redundant
## Severity
**MEDIUM** (score: 5.0/10)

A non-zone-redundant Event Hub Namespace is a regional-outage resilience concern affecting availability, not confidentiality or integrity.

## Summary
Ensures that an Azure Event Hubs namespace is deployed in a region that supports Availability Zone redundancy, since zone redundancy for Event Hubs is determined automatically by the deployment region rather than an explicit toggle.

## Applicability
- **Terraform**: `azurerm_eventhub_namespace` — inspects the `location` attribute against a hard-coded allow-list of zone-redundancy-capable Azure regions

## Why it matters
Event Hubs is frequently used as the backbone for real-time data ingestion pipelines (telemetry, IoT, clickstreams, log aggregation) where availability directly affects downstream systems' ability to receive and process events. Unlike many other Azure services where zone redundancy is an explicit resource property, Azure Event Hubs' zone redundancy is automatically enabled by the platform when the namespace is deployed into a region that has three or more Availability Zones and supports this capability — there is no separate flag to set. Consequently, the practical control available to operators is the choice of deployment `location`: deploying a namespace into a region that does not support zone redundancy means the namespace's underlying infrastructure lacks protection against a single-datacenter/zone failure, creating a risk of ingestion pipeline downtime or data loss during a localized outage, even though the service tier and configuration otherwise look identical to a zone-redundant deployment elsewhere.

## How Checkov evaluates this
The check inspects the `location` attribute of `azurerm_eventhub_namespace` and compares it (in both the human-readable form, e.g. `"East US"`, and the normalized/no-space lowercase form, e.g. `"eastus"`) against a hard-coded list (`LOCATIONS_W_REDUNDANCY`) of Azure regions known to support zone redundancy (spanning Asia Pacific, Canada, Europe, Mexico, Middle East, South America, and select US regions). The check **PASSES** if `location` matches one of the listed region names/codes; it **FAILS** if the namespace is deployed to any region not in that list. Because Checkov's list is a point-in-time snapshot of Azure's regional zone support, it may lag behind Azure adding zone support to additional regions over time — treat a FAIL as "region not yet on Checkov's known-good list" and verify current Azure documentation if a region is missing that you believe now supports zones.

## Non-compliant example
```hcl
resource "azurerm_eventhub_namespace" "example" {
  name                = "example-ehns"
  location            = "West US"   # not in the zone-redundancy-capable region list
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"
}
```

## Remediated example
```hcl
resource "azurerm_eventhub_namespace" "example" {
  name                = "example-ehns"
  location            = "East US"   # region supports availability-zone redundancy
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"
}
```

## Remediation steps
1. Deploy (or redeploy) the `azurerm_eventhub_namespace` resource into one of the Azure regions known to support zone redundancy (e.g., `East US`, `West Europe`, `Southeast Asia`, `Australia East`, etc. — see the check source for the full current list).
2. Since `location` is generally immutable for an existing namespace, moving to a zone-redundant region for an existing namespace typically requires creating a new namespace in the target region and migrating consumers/producers, rather than an in-place change — plan for a cutover window.
3. Confirm the chosen SKU tier actually provisions zone-redundant infrastructure in that region for your workload (zone redundancy applies automatically based on region for supported tiers; verify current Azure documentation, since capabilities can evolve).
4. Update any region-specific compliance/data-residency requirements against the new target region before migrating, since moving regions may have data sovereignty implications.
5. Re-run Checkov after deployment to confirm the new region is recognized as zone-redundant by the current version of the check (the allow-list may need to be updated over time as Azure adds zone support to more regions).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventHubNamespaceZoneRedundant.py
- Azure docs: https://learn.microsoft.com/en-us/azure/reliability/reliability-event-hubs
