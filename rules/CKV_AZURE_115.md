# CKV_AZURE_115: Ensure that AKS enables private clusters
## Severity
**LOW** (score: 2.0/10)

A publicly reachable Kubernetes API server exposes the AKS control plane to internet-wide reconnaissance and attack, so credential leaks, RBAC misconfigurations, or API server vulnerabilities become directly exploitable without prior network access.

## Summary
This check verifies that an Azure Kubernetes Service (AKS) cluster's control plane (API server) is deployed as a private cluster, so the Kubernetes API is only reachable over a private network rather than a public endpoint.

## Applicability
- **IaC framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_kubernetes_cluster`

## Why it matters
By default, AKS clusters expose their Kubernetes API server on a public IP address. Anyone on the internet can reach the API server endpoint, and the cluster's security then depends entirely on authentication (client certs, Azure AD tokens) and any IP allow-listing you've configured. This creates a significant attack surface: API server credential leaks, misconfigured RBAC, or unpatched Kubernetes API vulnerabilities become directly exploitable from the internet rather than requiring network-level access first. Enabling a private cluster puts the API server behind a private endpoint inside your virtual network (backed by Azure Private Link), so only clients with network access to that VNet (via VPN, ExpressRoute, peering, or a jump host) can even attempt to reach `kubectl`/API traffic. This is defense-in-depth: it doesn't replace authentication/authorization, but it removes an entire class of opportunistic internet-based reconnaissance and attack against the control plane.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `private_cluster_enabled` attribute on `azurerm_kubernetes_cluster`:
- **PASS** if `private_cluster_enabled = true`.
- **FAIL** if the attribute is `false` or omitted (the resource-value-check default behavior treats a missing/falsey value as failing).

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "aks-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "aksexample"

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
  # private_cluster_enabled not set -> public API server endpoint
}
```

## Remediated example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "aks-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "aksexample"

  private_cluster_enabled = true  # API server is only reachable via private endpoint

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Set `private_cluster_enabled = true` on the `azurerm_kubernetes_cluster` resource.
2. Note this generally must be set at cluster creation time — converting an existing public cluster to private typically requires recreating the cluster (Terraform will show a resource replacement).
3. Ensure your CI/CD runners, admin workstations, or bastion hosts have network connectivity (VNet peering, VPN, ExpressRoute, or a jump box inside the VNet) to reach the private API endpoint, since `kubectl` will no longer work from the open internet.
4. Consider also configuring `private_dns_zone_id` if you need custom DNS resolution behavior for the private endpoint.
5. If you need occasional public access for specific IP ranges instead of full private-only mode, look at `api_server_access_profile` / authorized IP ranges as an alternative or complement.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSEnablesPrivateClusters.py)
- [Azure AKS private clusters documentation](https://learn.microsoft.com/en-us/azure/aks/private-clusters)
