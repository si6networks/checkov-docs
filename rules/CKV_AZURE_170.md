# CKV_AZURE_170: Ensure that AKS use the Paid Sku for its SLA

## Severity
**LOW** (score: 2.0/10)

Using the Free SKU instead of a paid tier only affects the AKS control-plane SLA/uptime guarantee, an availability concern with no direct security exposure.

## Summary
This check ensures that an AKS cluster's `sku_tier` is set to `Standard` (paid, SLA-backed control plane) rather than the free tier, which carries no uptime SLA.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_kubernetes_cluster` (`sku_tier`).

## Why it matters
The AKS control plane (API server, etcd, scheduler) is managed by Microsoft. On the free tier, there is no financially-backed SLA on control plane availability, and the free control plane is also subject to lower API server throughput/scale limits. For production workloads, an unavailable or degraded API server means you cannot deploy, scale, roll back, or otherwise react to an incident even if your worker nodes and pods are fine — the control plane is a single point of failure for cluster operations. The Standard (paid) tier provides a guaranteed uptime SLA and higher API server availability/scale limits, which is a baseline reliability requirement for anything customer-facing or business-critical.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (`AKSIsPaidSku`) that inspects the `sku_tier` attribute and expects the value `"Standard"`. Any other value (including the default `"Free"`, or its historical alias) causes the check to **FAIL**; `sku_tier = "Standard"` **PASSES**.

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  name                = "myAksCluster"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "myaks"
  # sku_tier not set -> defaults to "Free", no SLA

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediated example
```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  name                = "myAksCluster"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "myaks"
  sku_tier            = "Standard"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Set `sku_tier = "Standard"` on the `azurerm_kubernetes_cluster` resource.
2. Changing `sku_tier` on an existing cluster is supported as an in-place update in current AKS/provider versions, but verify against your provider version — older versions may require replacement.
3. Budget for the additional per-hour control-plane cost incurred by the Standard tier.
4. For clusters requiring guaranteed API server availability across zones, pair this with the AKS Uptime SLA and consider the "Premium" tier (long-term support) if extended Kubernetes version support is also needed.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSIsPaidSku.py
- Microsoft Docs: https://learn.microsoft.com/en-us/azure/aks/free-standard-pricing-tiers
