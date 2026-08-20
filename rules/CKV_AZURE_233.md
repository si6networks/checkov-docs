# CKV_AZURE_233: Ensure Azure Container Registry (ACR) is zone redundant

## Severity
**LOW** (score: 2.0/10)

Missing zone redundancy in Azure Container Registry is a resilience/availability concern for image delivery during a regional zone failure, not a direct confidentiality or integrity risk.

## Summary
This check ensures an Azure Container Registry (and any of its geo-replications) is configured with zone redundancy enabled, so registry data is resilient to a single Availability Zone outage.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_container_registry` resources — inspects `zone_redundancy_enabled` on the registry itself, and `zone_redundancy_enabled` within each `georeplications` block.
- **ARM/Bicep**: `Microsoft.ContainerRegistry/registries` and `Microsoft.ContainerRegistry/registries/replications` — inspects `properties.zoneRedundancy`.

## Why it matters
Container registries are a critical dependency for deployments, autoscaling, node reboots, and CI/CD — if the registry is unreachable, new pods/containers can't pull images, blocking deployments and potentially blocking node/pod recovery during an incident. A registry without zone redundancy has all its data and endpoints tied to a single Availability Zone; if that zone has an outage, image pulls can fail cluster/fleet-wide at exactly the moment infrastructure is trying to reschedule or recover workloads (e.g., after a node failure), compounding the original incident. Zone redundancy (Premium SKU only) replicates registry content across zones so a single-zone failure doesn't take down image availability, which matters most for production clusters using rolling deploys, autoscaling, or frequent node churn.

## How Checkov evaluates this
- **Terraform** (`ACREnableZoneRedundancy.py`): requires `zone_redundancy_enabled == [True]` on the registry itself. It then also iterates any `georeplications` blocks and requires each one's `zone_redundancy_enabled` to be `[True]` as well — if the primary registry or any single georeplication lacks it, the check FAILS.
- **ARM** (`ACREnableZoneRedundancy.py`): reads `properties.zoneRedundancy`. The check FAILS only if this is explicitly set to the string `"Disabled"`; any other value (including absent, which defaults to disabled in Azure but is not explicitly flagged by this particular ARM check) PASSES per this implementation — note the ARM logic is looser than the Terraform logic, which requires an explicit `true`.

## Non-compliant example
```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Premium"
  admin_enabled       = false
  # zone_redundancy_enabled not set -> defaults to false, FAILS

  georeplications {
    location                = "westeurope"
    zone_redundancy_enabled = false
  }
}
```

## Remediated example
```hcl
resource "azurerm_container_registry" "example" {
  name                    = "exampleacr"
  resource_group_name     = azurerm_resource_group.example.name
  location                = azurerm_resource_group.example.location
  sku                     = "Premium"
  admin_enabled           = false
  zone_redundancy_enabled = true   # <-- primary registry, PASSES

  georeplications {
    location                = "westeurope"
    zone_redundancy_enabled = true   # <-- replica also zone redundant, PASSES
  }
}
```

## Remediation steps
1. Ensure the registry's SKU is `Premium` — zone redundancy is not available on Basic or Standard tiers.
2. Set `zone_redundancy_enabled = true` on the `azurerm_container_registry` resource itself.
3. Set `zone_redundancy_enabled = true` on every `georeplications` block, if geo-replication is used — a partially-enabled replica set will still fail this check.
4. Confirm each target region (primary and all replication regions) supports Availability Zones; not all Azure regions do.
5. Note this may require a SKU upgrade with associated cost increase; evaluate whether the registry's criticality justifies Premium + zone redundancy versus a lower tier for non-production registries.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACREnableZoneRedundancy.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/ACREnableZoneRedundancy.py
- Azure docs: https://learn.microsoft.com/en-us/azure/container-registry/zone-redundancy
