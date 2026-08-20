# CKV_AZURE_165: Ensure geo-replicated container registries to match multi-region container deployments

## Severity
**MEDIUM** (score: 5.0/10)

This is an availability/resilience best practice (geo-replication for multi-region deployments) with no direct confidentiality or integrity impact if omitted.

## Summary
This check ensures that an Azure Container Registry configured for multi-region use is on the Premium SKU with `georeplications` configured, so image pulls remain available and fast across regions.

## Applicability
- **Terraform**: `azurerm_container_registry` resource.

## Why it matters
When container images are deployed across multiple Azure regions but the backing registry lives in a single region without geo-replication, every regional deployment/scale-out event and every node pull in a distant region incurs cross-region network latency and, more importantly, becomes a single-region dependency: if that one region has an outage, all regions lose the ability to pull images, breaking rolling updates, autoscaling, and node recovery everywhere — not just in the affected region. This turns a regional Azure incident into a global deployment outage. Geo-replication keeps a synchronized copy of the registry in each target region so pulls are local and resilient to a single-region failure.

## How Checkov evaluates this
The check (`ACRGeoreplicated`) looks at the resource's `sku` attribute and the `georeplications` attribute:
- If `sku == "Premium"` **and** `georeplications` is set (non-empty), the check **PASSES**.
- Otherwise (non-Premium SKU, or Premium without any `georeplications` block), it **FAILS**.

Geo-replication is a Premium-tier-only ACR feature, so both conditions are required together.

## Non-compliant example
```hcl
resource "azurerm_container_registry" "acr" {
  name                = "myregistry"
  resource_group_name = azurerm_resource_group.rg.name
  location            = "eastus"
  sku                 = "Premium"
  # No georeplications block, despite multi-region AKS deployments
}
```

## Remediated example
```hcl
resource "azurerm_container_registry" "acr" {
  name                = "myregistry"
  resource_group_name = azurerm_resource_group.rg.name
  location            = "eastus"
  sku                 = "Premium"

  georeplications {
    location                = "westeurope"
    zone_redundancy_enabled = true
  }

  georeplications {
    location                = "southeastasia"
    zone_redundancy_enabled = true
  }
}
```

## Remediation steps
1. Confirm the ACR SKU is `Premium` (required for geo-replication).
2. Add one `georeplications` block per additional region where you deploy containers, matching your AKS/App Service/ACI regional footprint.
3. Enable `zone_redundancy_enabled` in each replicated region for additional resilience against zone-level failures.
4. Be aware that adding/removing georeplications can take time to provision and may incur additional storage/egress cost per replicated region.
5. If the registry is genuinely single-region by design, this finding can be a false positive — but confirm no other region's workloads pull from it before suppressing.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRGeoreplicated.py
