# CKV_AZURE_212: Ensure App Service has a minimum number of instances for failover
## Severity
**MEDIUM** (score: 4.5/10)

A single-instance App Service Plan has no failover capacity, so an unplanned interruption can take the application offline; this is an availability risk rather than a direct confidentiality or integrity exploit path.

## Summary
Ensures that an Azure App Service (Web App) is configured with more than one worker/instance so it can tolerate a single-instance failure without downtime.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_service_plan` (checks the `worker_count` attribute)
- **ARM**: `Microsoft.Web/sites`, `Microsoft.Web/sites/slots` (checks `properties.siteConfig.numberOfWorkers`)
- **Bicep**: compiles to the same ARM resource types above and is covered by the ARM check

## Why it matters
App Service Plans allow you to run one or more "worker" instances of your app. When only a single instance is provisioned, the app becomes a single point of failure: any unplanned interruption — a host reboot, hardware fault, in-place OS patching, or an Azure-initiated healing action — takes the entire application offline until Azure automatically self-heals the instance. While Azure App Service does attempt automatic recovery of unhealthy instances, that recovery is not instantaneous, and during the recovery window all requests to the app fail or time out. Running two or more instances lets the App Service load balancer route traffic away from an unhealthy instance while it recovers, eliminating the single point of failure and enabling zero-downtime scaling and patching operations.

## How Checkov evaluates this
- **Terraform** (`azurerm_service_plan`): reads `worker_count`. If the attribute is present, is an integer, and its value is greater than `1`, the check **PASSES**. If `worker_count` is absent, not an integer, or `<= 1`, it **FAILS**. If the value can't be resolved to an `int` (e.g., an unresolved variable), the result is `UNKNOWN`.
- **ARM**: reads `properties.siteConfig.numberOfWorkers`. Same pass condition — an integer value greater than `1` passes; otherwise the resource fails. Absence of `siteConfig` or `numberOfWorkers` results in `FAILED`.

## Non-compliant example
```hcl
resource "azurerm_service_plan" "example" {
  name                = "example-plan"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  os_type             = "Linux"
  sku_name            = "P1v2"
  worker_count        = 1
}
```

## Remediated example
```hcl
resource "azurerm_service_plan" "example" {
  name                = "example-plan"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  os_type             = "Linux"
  sku_name            = "P1v2"
  worker_count        = 2   # run at least 2 instances for failover
}
```

## Remediation steps
1. Set `worker_count` (Terraform) or `properties.siteConfig.numberOfWorkers` (ARM/Bicep) to a value of `2` or greater on the App Service Plan.
2. Confirm the chosen SKU tier supports multiple instances (the `Free` and `Shared` tiers do not support scaling to multiple workers — use at least `Basic` or, preferably, `Standard`/`PremiumV2`/`PremiumV3` for production workloads).
3. For true failover/HA, pair a multi-instance plan with `zone_balancing_enabled`/zone redundancy where the region and SKU support it (see CKV_AZURE_225).
4. Consider enabling autoscale rules so the instance count can grow under load rather than relying on a fixed high `worker_count` at all times.
5. This change does not require destroying the resource — Terraform will perform an in-place update to scale the plan.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceInstanceMinimum.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceInstanceMinimum.py
