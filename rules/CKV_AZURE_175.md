# CKV_AZURE_175: Ensure Web PubSub uses a SKU with an SLA

## Severity
**LOW** (score: 2.0/10)

Using the Free SKU for Web PubSub only affects the availability SLA, not confidentiality or integrity of the service.

## Summary
This check ensures that an Azure Web PubSub resource is not deployed on the `Free_F1` SKU, which carries no availability SLA.

## Applicability
- **Terraform**: `azurerm_web_pubsub` (`sku`).
- **ARM/Bicep**: `Microsoft.SignalRService/webPubSub` (`sku.name`).

## Why it matters
The `Free_F1` tier for Azure Web PubSub is intended for development, evaluation, and low-scale prototyping — it has strict connection/message quotas and, critically, no financially-backed uptime SLA from Microsoft. Using it for a production real-time messaging workload (chat, live notifications, IoT telemetry fan-out, collaborative apps) means there is no guaranteed availability commitment, and the service is subject to throttling limits that can silently drop connections or messages under real traffic. This is a reliability/availability concern rather than a confidentiality/integrity one: a production dependency on a free tier resource risks unplanned outages and degraded service with no recourse.

## How Checkov evaluates this
This is a negative-value check that inspects the SKU name and **FAILS** if it equals `"Free_F1"`. Any other SKU (e.g., `Standard_S1`, `Premium_P1`) **PASSES**.
- **Terraform** inspects `sku`.
- **ARM** inspects `sku/name`.

## Non-compliant example
```hcl
resource "azurerm_web_pubsub" "pubsub" {
  name                = "my-webpubsub"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Free_F1"
  capacity            = 1
}
```

## Remediated example
```hcl
resource "azurerm_web_pubsub" "pubsub" {
  name                = "my-webpubsub"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Standard_S1"
  capacity            = 1
}
```

## Remediation steps
1. Change `sku` (Terraform) or `sku.name` (ARM/Bicep) from `Free_F1` to an SLA-backed tier such as `Standard_S1` or `Premium_P1`.
2. Right-size `capacity`/unit count based on expected concurrent connection count and message throughput for the chosen SKU.
3. Changing SKU on an existing resource may or may not require replacement depending on provider version — check the plan output before applying in production.
4. Budget accordingly, as paid tiers are billed per unit/hour rather than being free.
5. If this is genuinely a dev/test resource, this finding can be suppressed for that specific resource rather than remediated.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PubsubSKUSLA.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/PubsubSKUSLA.py
- Microsoft Docs: https://learn.microsoft.com/en-us/azure/azure-web-pubsub/reference-pricing-tier
