# CKV_AZURE_225: Ensure the App Service Plan is zone redundant
## Severity
**MEDIUM** (score: 5.0/10)

A non-zone-redundant App Service Plan is a resilience/availability concern tied to datacenter-level outages, with no direct confidentiality or integrity impact.

## Summary
Ensures that an Azure App Service Plan is configured for zone redundancy, distributing its instances across multiple Availability Zones within a region.

## Applicability
- **Terraform**: `azurerm_service_plan` — inspects `zone_balancing_enabled`
- **ARM**: `Microsoft.Web/serverfarms` — inspects `properties.zoneRedundant`
- **Bicep**: compiles to the ARM resource type above

## Why it matters
Availability Zones are physically separate datacenter groupings within an Azure region, each with independent power, cooling, and networking. Without zone redundancy, all instances of an App Service Plan are placed within a single zone (or without zone awareness at all), meaning a zone-level failure — a datacenter outage, a power event, or a regional infrastructure incident affecting one zone — can take down the entire application even if the plan has multiple instances, since all those instances may reside in the same failure domain. This undermines the resiliency benefit that scaling to multiple instances (see CKV_AZURE_212) is meant to provide. Enabling zone redundancy spreads instances across zones so that a single zone outage only affects a subset of instances, and Azure automatically rebalances/replaces capacity in the surviving zones — providing meaningfully higher availability for business-critical workloads at no additional cost over an equivalently-sized non-zone-redundant plan.

## How Checkov evaluates this
- **Terraform**: inspects `zone_balancing_enabled`. The check has no `missing_block_result` override specified, so the default `BaseResourceValueCheck` behavior applies — the check **PASSES** only when the attribute is explicitly `true`; it **FAILS** if `false` or omitted.
- **ARM**: inspects `properties.zoneRedundant`, with `missing_block_result=CheckResult.FAILED` explicitly set — so an absent `zoneRedundant` property is treated as **FAILED**, and it **PASSES** only when explicitly `true`.

## Non-compliant example
```hcl
resource "azurerm_service_plan" "example" {
  name                = "example-plan"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  os_type             = "Linux"
  sku_name            = "P1v3"

  # zone_balancing_enabled left unset -> defaults to false
}
```

## Remediated example
```hcl
resource "azurerm_service_plan" "example" {
  name                    = "example-plan"
  resource_group_name     = azurerm_resource_group.example.name
  location                = azurerm_resource_group.example.location
  os_type                 = "Linux"
  sku_name                = "P1v3"
  zone_balancing_enabled  = true   # spread instances across availability zones
  worker_count            = 3      # zone redundancy requires at least 3 (or a multiple of 3) instances
}
```

## Remediation steps
1. Set `zone_balancing_enabled = true` (Terraform) or `properties.zoneRedundant: true` (ARM/Bicep) on the App Service Plan.
2. Confirm the SKU supports zone redundancy — this generally requires a Premium v2/v3 (or higher) SKU; Basic/Standard/Free tiers typically do not support it.
3. Ensure the plan's `worker_count` is set appropriately (Azure recommends at least 3 instances, or multiples of 3, to evenly balance across the typical 3 availability zones in a region) — a zone-redundant plan with too few instances won't achieve meaningful redundancy.
4. Confirm the target Azure region actually supports Availability Zones — not all regions do; deploying a zone-redundant plan in a non-zone-supporting region will fail.
5. Note this setting typically can only be set at plan creation and may require replacing the App Service Plan if changing an existing non-zone-redundant plan — validate whether an in-place update is supported for your provider version before assuming zero downtime.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServicePlanZoneRedundant.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServicePlanZoneRedundant.py
- Azure docs: https://learn.microsoft.com/en-us/azure/reliability/reliability-app-service
