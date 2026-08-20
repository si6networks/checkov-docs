# CKV_AZURE_143: Ensure AKS cluster nodes do not have public IP addresses
## Severity
**HIGH** (score: 8.0/10)

Assigning public IP addresses to AKS node pool nodes exposes the underlying Kubernetes worker VMs directly to the internet, materially expanding the attack surface for host-level compromise of the cluster.

## Summary
This check ensures the default node pool of an Azure Kubernetes Service (AKS) cluster is not configured to assign public IP addresses directly to individual worker nodes.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_kubernetes_cluster` resource, `default_node_pool` block, attributes `enable_node_public_ip` / `node_public_ip_enabled`.

## Why it matters
Giving AKS worker nodes their own public IP addresses exposes each node's kubelet, and potentially other node-level services/ports, directly to the internet, bypassing whatever perimeter controls (load balancer, NSG on the cluster subnet, Azure Firewall) are meant to be the sole ingress path. A publicly reachable node is a prime target for internet-wide port scanning and exploitation of any exposed kubelet API, container runtime socket, or misconfigured hostNetwork pod; a compromised node gives an attacker a foothold inside the cluster's network with access to node-mounted secrets, other pods' traffic on the same node, and potential lateral movement to the rest of the cluster. Keeping nodes on private IPs only, with a single controlled ingress (e.g. through a load balancer/App Gateway/Ingress controller with proper NSGs), significantly reduces the cluster's internet-facing attack surface.

## How Checkov evaluates this
The check inspects `default_node_pool[0]`, checking both possible attribute names used across provider versions: `enable_node_public_ip` and its renamed successor `node_public_ip_enabled`. If either is set to `[True]`, the check FAILS. Otherwise (both absent or `false`), it PASSES — the provider default is no public IP per node.

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  default_node_pool {
    name                  = "default"
    node_count            = 3
    vm_size               = "Standard_DS2_v2"
    node_public_ip_enabled = true  # FAILS -- nodes directly internet-reachable
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
    name                   = "default"
    node_count             = 3
    vm_size                = "Standard_DS2_v2"
    node_public_ip_enabled = false  # nodes only have private IPs
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Set `node_public_ip_enabled = false` (or `enable_node_public_ip = false` on older provider versions) in the `default_node_pool` block — and in any additional `azurerm_kubernetes_cluster_node_pool` resources, which are not covered by this specific check but should follow the same practice.
2. This attribute typically forces node pool recreation if changed on an existing cluster/node pool — plan a blue/green node pool migration or accept a maintenance window.
3. Expose services externally through a Kubernetes `LoadBalancer` Service (backed by Azure Load Balancer), an Ingress controller, or Application Gateway Ingress Controller (AGIC) instead of direct node public IPs.
4. If outbound internet access from nodes is needed (e.g. pulling images, calling external APIs), use a NAT Gateway or the AKS-managed outbound type rather than per-node public IPs, which only affects inbound exposure risk but is worth aligning for consistent architecture.
5. Combine with restrictive NSGs on the AKS subnet and, where required, API server authorized IP ranges for full perimeter control.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNodePublicIpDisabled.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/aks/use-node-public-ips
