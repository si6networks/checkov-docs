# CKV_AZURE_196: Ensure that SignalR uses a Paid Sku for its SLA

## Severity
**LOW** (score: 2.0/10)

Using the free SignalR SKU is primarily an availability/SLA and feature-capacity limitation rather than a direct security exposure.

## Summary
This check ensures an Azure SignalR Service resource does not use the `Free_F1` SKU, which carries no availability SLA and imposes hard connection/message limits unsuitable for production use.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (`azurerm` provider)
- **Resource type:** `azurerm_signalr_service`

## Why it matters
The `Free_F1` SKU for Azure SignalR Service is explicitly a development/evaluation tier: Microsoft provides no financially-backed SLA for it, and it is capped at a small number of concurrent connections and daily messages. A production application relying on `Free_F1` has no availability guarantee at all — an outage or capacity exhaustion (e.g. hitting the daily message cap) can silently disconnect real-time clients (chat, notifications, live dashboards) with no contractual recourse and, depending on the failure mode, no early warning before the connection/message ceiling is hit. This is a reliability/business-continuity control: using a paid `Standard` (or `Premium`) SKU is a prerequisite for Microsoft's SLA to apply and for the service to scale to production-level connection counts.

## How Checkov evaluates this
This is a negative-value check on `sku[0].name`. If the value equals the forbidden value `"Free_F1"`, the check FAILS. Any other SKU name (`Standard_S1`, `Premium_P1`, `Premium_P2`, etc.) PASSES. Note that unlike some other negative-value checks in this batch, this one does not override `missing_attribute_result`, so if the `sku` block is entirely absent, the default base-class behavior applies (typically treated as passing/unknown depending on Checkov version, since there's no forbidden value present to match).

## Non-compliant example
```hcl
resource "azurerm_signalr_service" "example" {
  name                = "example-signalr"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku {
    name     = "Free_F1"
    capacity = 1
  }
}
```

## Remediated example
```hcl
resource "azurerm_signalr_service" "example" {
  name                = "example-signalr"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku {
    name     = "Standard_S1"
    capacity = 1
  }
}
```

## Remediation steps
1. Identify any `azurerm_signalr_service` resources using `sku.name = "Free_F1"`.
2. Change the SKU to a paid tier — `Standard_S1` for most production workloads, or `Premium_P1`/`Premium_P2` if you need geo-replication, higher scale units, or the Premium tier's availability zone support.
3. Size the `capacity` (unit count) attribute according to expected concurrent connection volume; each unit provides a fixed connection/message quota, and undersizing can still cause throttling even on a paid SKU.
4. Changing the SKU on an existing SignalR instance may briefly interrupt active connections during the resize; plan a maintenance window for production instances.
5. Reserve `Free_F1` strictly for local development/proof-of-concept work, and consider isolating such instances in a separate subscription or resource group so this check can be scoped appropriately.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SignalRSKUSLA.py
- [Azure SignalR Service pricing tier documentation](https://learn.microsoft.com/en-us/azure/azure-signalr/signalr-concept-pricing-tier)
