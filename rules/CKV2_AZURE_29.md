# CKV2_AZURE_29: Ensure AKS cluster has Azure CNI networking enabled
## Severity
**MEDIUM** (score: 5.0/10)

Using kubenet instead of Azure CNI limits fine-grained network policy enforcement and pod-level network security controls in AKS, weakening network segmentation but not by itself exposing the cluster.

## Summary
This check verifies that an Azure Kubernetes Service (AKS) cluster's network profile uses the Azure CNI network plugin rather than the basic `kubenet` plugin.

## Applicability
- **IaC framework:** Terraform (graph-based attribute check)
- **Resource type involved:** `azurerm_kubernetes_cluster`

## Why it matters
With `kubenet` (the alternative to Azure CNI), pods receive IP addresses from a separate, internal address space and communicate with the rest of the VNet through NAT and user-defined routes managed by Kubernetes. This makes pods invisible to native Azure networking constructs: you cannot apply Network Security Groups directly to pod IPs, cannot use Azure Network Policies at the pod level with the same fidelity, and integrating with peered VNets, on-prem networks (via ExpressRoute/VPN), or other Azure-native networking features (Private Link, Application Gateway backend pools targeting pods directly) is significantly more limited. Azure CNI assigns each pod a routable IP directly from the VNet's address space, which is required for proper network segmentation, NSG-based pod-level traffic control, and enterprise-grade network security postures. Running production, security-sensitive workloads on `kubenet` typically means weaker network isolation and reduced visibility for security tooling that expects pods to have real VNet IPs.

## How Checkov evaluates this
This is a **graph-based attribute check**:
- The `network_profile.network_plugin` attribute must be `within` the list `["azure", "Azure"]`.

Any other value — most notably `"kubenet"` — causes the resource to FAIL. (Values are compared case-sensitively against these two specific string variants for `"azure"`.)

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = "eastus"
  resource_group_name = "example-rg"
  dns_prefix          = "exampleaks"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "kubenet"
  }
}
```

## Remediated example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = "eastus"
  resource_group_name = "example-rg"
  dns_prefix          = "exampleaks"

  default_node_pool {
    name           = "default"
    node_count     = 3
    vm_size        = "Standard_DS2_v2"
    vnet_subnet_id = azurerm_subnet.aks.id
  }

  identity {
    type = "SystemAssigned"
  }

  # Fixed: use Azure CNI so pods get routable VNet IP addresses.
  network_profile {
    network_plugin = "azure"
  }
}
```

## Remediation steps
1. Set `network_profile.network_plugin = "azure"` on the `azurerm_kubernetes_cluster` resource.
2. Ensure the node subnet (`vnet_subnet_id`) is sized generously: Azure CNI reserves an IP address per pod (times max pods per node, times node count), which consumes significantly more address space than `kubenet` — undersized subnets are the most common Azure CNI migration failure.
3. **This is not an in-place change** — the network plugin is immutable on an existing AKS cluster. Migrating from `kubenet` to Azure CNI requires creating a new cluster (or using Azure's newer "Azure CNI Overlay" migration path if applicable) and migrating workloads; plan for a blue/green cluster cutover.
4. Consider `network_plugin = "azure"` with `network_plugin_mode = "overlay"` (Azure CNI Overlay) if you want CNI's networking benefits without consuming a full VNet IP per pod — evaluate against this check's exact matched values, since `azure` covers both classic and overlay CNI modes.
5. Re-validate any NSGs or route tables that assumed `kubenet`'s NAT-based pod networking, since pod traffic will now appear with real VNet-routable source IPs.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureAKSclusterAzureCNIEnabled.json)
- [Azure CNI networking in AKS](https://learn.microsoft.com/en-us/azure/aks/configure-azure-cni)
