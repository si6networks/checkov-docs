# CKV_AZURE_232: Ensure that only critical system pods run on system nodes

## Severity
**HIGH** (score: 7.5/10)

Allowing application pods to schedule on AKS system nodes lets a misbehaving or compromised workload disrupt critical cluster system components, harming availability and enabling limited blast-radius escalation within the cluster.

## Summary
This check ensures an AKS cluster's default (system) node pool is tainted with `CriticalAddonsOnly=true:NoSchedule`, so only critical system pods can be scheduled there and application workloads are kept off system nodes.

## Applicability
- **Terraform**: `azurerm_kubernetes_cluster` resources — inspects `default_node_pool[0].only_critical_addons_enabled`.

## Why it matters
AKS system node pools run essential platform components (CoreDNS, metrics-server, tunnelfront/konnectivity, kube-proxy, etc.) needed for cluster operation. If application pods are allowed to schedule onto the same nodes, a misbehaving, resource-hungry, or malicious workload can starve those nodes of CPU/memory/disk, causing node pressure evictions that take down critical system pods along with it. This can cascade into cluster-wide failures: DNS resolution breaking, the control plane losing connectivity to nodes, or metrics/autoscaling failing — none of which are limited to the offending pod's own namespace. A compromised or buggy application container sharing a system node also has a shorter path to interfering with cluster-critical processes than if it were isolated on a dedicated user node pool.

Setting `only_critical_addons_enabled = true` applies the `CriticalAddonsOnly=true:NoSchedule` taint to the system pool, so ordinary application pods (which lack the matching toleration) cannot be scheduled there — they get placed on separate user node pools instead.

## How Checkov evaluates this
`BaseResourceValueCheck` inspecting `default_node_pool[0].only_critical_addons_enabled` on `azurerm_kubernetes_cluster`. The check PASSES only if this is explicitly `true`; it FAILS if omitted or `false`.

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  default_node_pool {
    name       = "system"
    node_count = 2
    vm_size    = "Standard_D2_v2"
    # only_critical_addons_enabled not set -> application pods can land here, FAILS
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediated example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  default_node_pool {
    name                         = "system"
    node_count                  = 2
    vm_size                     = "Standard_D2_v2"
    only_critical_addons_enabled = true   # <-- taints system pool, PASSES
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "user" {
  name                  = "userpool"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.example.id
  vm_size               = "Standard_D2_v2"
  node_count            = 2
  mode                  = "User"
}
```

## Remediation steps
1. Set `only_critical_addons_enabled = true` on the cluster's `default_node_pool` block.
2. Add at least one separate `azurerm_kubernetes_cluster_node_pool` resource with `mode = "User"` to host application workloads, since ordinary pods will no longer schedule on the tainted system pool.
3. This is an in-place-incompatible change on an existing cluster in some scenarios — verify with `terraform plan` whether it forces node pool recreation, and coordinate a rollout window if so.
4. Confirm any DaemonSets or add-ons you rely on that are not part of AKS's built-in critical add-ons carry an explicit toleration for `CriticalAddonsOnly` if they genuinely need to run on system nodes; otherwise they'll simply move to user nodes, which is usually fine.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSOnlyCriticalPodsOnSystemNodes.py
- Azure docs: https://learn.microsoft.com/en-us/azure/aks/use-system-pools
