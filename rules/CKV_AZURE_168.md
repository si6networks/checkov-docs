# CKV_AZURE_168: Ensure Azure Kubernetes Cluster (AKS) nodes should use a minimum number of 50 pods

## Severity
**LOW** (score: 2.0/10)

A low max-pods ceiling is an availability/capacity-planning concern (forces more nodes or causes scheduling pressure) rather than a confidentiality or integrity risk.

## Summary
This check ensures that AKS node pools are configured to allow at least 50 pods per node, rather than the low Azure CLI/portal default of 30.

## Applicability
- **Terraform**: `azurerm_kubernetes_cluster` (default node pool) and `azurerm_kubernetes_cluster_node_pool` (additional pools).
- **ARM/Bicep**: `Microsoft.ContainerService/managedClusters` and `Microsoft.ContainerService/managedClusters/agentPools`.

## Why it matters
The `max-pods` setting bounds how many pods the kubelet will schedule onto a single node — it exists primarily because Azure CNI (in its non-overlay default configuration) pre-allocates an IP address per pod from the VNet subnet, so it directly constrains IP address consumption and node density. A max-pods value that's too low (the historical default of 30) forces the cluster autoscaler to add more nodes than necessary to serve the same workload, which increases infrastructure cost, increases the blast radius of node-level failures being spread across more machines, and can silently cap scheduling capacity during a traffic spike — pods will stay `Pending` on nodes that are otherwise CPU/memory-idle purely because the pod-count ceiling was reached. Raising the minimum to 50 is Microsoft's own AKS baseline recommendation to avoid under-provisioned node pods.

## How Checkov evaluates this
- **Terraform**: Defaults `max_pods` to `30` (the provider's implicit default). If `max_pods` is set directly on the resource, or on a `default_node_pool` block, its value is used. If the effective value is less than `50`, the check **FAILS**; `50` or higher **PASSES**.
- **ARM**: Reads `properties.maxPods`, or `properties.agentPoolProfiles[0].maxPods` if present, defaulting to `30` if unset. Same `< 50` threshold applies.

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  name                = "myAksCluster"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "myaks"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2_v2"
    # max_pods not set -> defaults to 30, below the 50 minimum
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

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2_v2"
    max_pods   = 50
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Set `max_pods` explicitly to `50` or higher on the `default_node_pool` block and on every `azurerm_kubernetes_cluster_node_pool` resource.
2. `max_pods` can only be set at node pool creation time in AKS — changing it on an existing pool requires creating a new node pool and migrating workloads (this is a Terraform `ForceNew`/replacement attribute).
3. If using Azure CNI Overlay or kubenet, IP exhaustion concerns differ; still verify the appropriate max-pods ceiling for your node SKU (CPU/memory) rather than leaving the low default.
4. Coordinate with subnet sizing — Azure CNI (non-overlay) needs enough available IPs per node to support the configured max-pods value; validate subnet CIDR capacity before raising this.
5. For ARM/Bicep, set `properties.agentPoolProfiles[].maxPods` (or `properties.maxPods` on top-level clusters) to at least `50`.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSMaxPodsMinimum.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AKSMaxPodsMinimum.py
