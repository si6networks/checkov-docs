# CKV_AZURE_211: Ensure App Service plan suitable for production use

## Severity
**LOW** (score: 2.0/10)

Using Free/Shared/Basic App Service plan tiers mainly forgoes SLA guarantees, autoscaling, and VNet integration for production workloads, which is largely a reliability/isolation best practice rather than a direct, exploitable vulnerability.

## Summary
This check ensures an Azure App Service Plan uses a SKU tier suitable for production workloads, flagging the Free (`F1`), Shared (`D1`), and Basic (`B1`/`B2`/`B3`) tiers as unsuitable.

## Applicability
- **Framework:** Terraform
- **Resource type:** `azurerm_service_plan`

## Why it matters
Although framed as a "production suitability" check rather than a pure security control, the Free, Shared, and Basic App Service plan tiers lack features that are directly security- and reliability-relevant: they do not support auto-scaling (making the app more susceptible to denial-of-service via resource exhaustion under load spikes), lack SLA guarantees (no contractual uptime commitment, meaning outages have no remediation path), and — critically for security — Basic and lower tiers do not support VNet integration or many advanced networking/isolation features available in Standard/Premium tiers, along with limited support for custom domains/deployment slots that are often used for blue-green/staged rollout patterns that reduce deployment risk. Running production, especially customer-facing or sensitive workloads, on these entry-level tiers leaves the application without the availability, scaling, and network isolation controls expected of a production-grade deployment.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck`:
- **Inspected key:** `sku_name`
- **Forbidden values:** `["B1", "B2", "B3", "F1", "D1"]`
- The check FAILS if `sku_name` is any of the forbidden Free/Shared/Basic SKUs.
- The check PASSES for any other SKU (e.g. Standard `S1`/`S2`/`S3`, Premium `P1v2`/`P1v3`, Isolated `I1`/`I1v2`, etc.).

## Non-compliant example
```hcl
resource "azurerm_service_plan" "example" {
  name                = "example-plan"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  os_type             = "Linux"
  sku_name            = "B1"   # Basic tier - not suitable for production
}
```

## Remediated example
```hcl
resource "azurerm_service_plan" "example" {
  name                = "example-plan"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  os_type             = "Linux"
  sku_name            = "P1v3"   # Premium tier - production-suitable
}
```

## Remediation steps
1. Change `sku_name` to a Standard (`S1`–`S3`), Premium (`P1v2`/`P1v3` etc.), or Isolated (`I1`–`I3`/`v2`) tier depending on the scaling, networking, and isolation needs of the workload.
2. Prefer PremiumV3 (`P*v3`) for new production deployments — it offers the newest hardware generation and best price/performance among current SKUs, per Microsoft's guidance referenced in the check's own source comments.
3. Changing `sku_name` on an existing plan is generally an in-place scale operation, but verify compatibility (e.g. some SKU transitions require the plan to be recreated, and moving between OS types is not supported at all) before applying to a live plan with running apps.
4. Budget accordingly — Standard/Premium/Isolated tiers cost significantly more than Free/Basic; use Basic tier deliberately only for genuinely non-production environments (dev/test sandboxes) and consider tagging those resources to make the exception intentional and auditable.
5. If VNet integration, private endpoints, or deployment slots are required, confirm the chosen SKU tier supports them (Basic supports slots in a limited form but not VNet integration; Standard and above are required for most enterprise networking features).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceSkuMinimum.py)
- [Azure App Service plan pricing tiers documentation](https://learn.microsoft.com/en-us/azure/app-service/overview-hosting-plans)
