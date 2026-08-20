# CKV_AZURE_7: Ensure AKS cluster has Network Policy configured
## Severity
**LOW** (score: 2.0/10)

Without a network policy engine, every pod can reach every other pod by default, so compromise of a single container enables unrestricted lateral movement across the cluster, bypassing intended isolation between workloads.

## Summary
This check fails when an Azure Kubernetes Service (AKS) cluster does not have a network policy engine (e.g. Azure or Calico) configured, meaning pod-to-pod traffic within the cluster is unrestricted by default.

## Applicability
Applies to Terraform (`azurerm_kubernetes_cluster`), ARM templates, and Bicep, for the resource type `Microsoft.ContainerService/managedClusters`.

## Why it matters
Without a NetworkPolicy engine, every pod in the AKS cluster can, by default, communicate with every other pod (and often with the underlying node network) with no restrictions — Kubernetes namespaces provide organizational and RBAC boundaries but not network isolation. This means that if any single container is compromised (through an application vulnerability, a malicious dependency, or a supply-chain attack), the attacker can move laterally to any other workload in the cluster, including services in namespaces that should be isolated for compliance or multi-tenancy reasons (e.g. reaching a database-tier pod directly, bypassing intended service-mesh or ingress-based access controls). Configuring a network policy provider (Azure Network Policy or Calico) enables the cluster to actually enforce `NetworkPolicy` resources, allowing teams to implement default-deny and least-privilege pod-to-pod communication, which is a foundational Kubernetes hardening control (and required by many compliance frameworks and the CIS Kubernetes Benchmark).

## How Checkov evaluates this
- ARM/Bicep: `apiVersion == "2017-08-31"` always FAILS (no `networkProfile` support existed in that version). Otherwise, it looks for `properties.networkProfile.networkPolicy` and PASSES if it is set to any truthy value (e.g. `"azure"` or `"calico"`); missing `properties`, `networkProfile`, or `networkPolicy` FAILS.
- Terraform: checks `network_profile[0].network_policy` on `azurerm_kubernetes_cluster` for any non-empty value (`ANY_VALUE`); if the attribute is unset, it FAILS.

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
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
    network_plugin = "azure"
    # network_policy omitted — no pod-to-pod traffic restriction possible
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
    name       = "default"
    node_count = 3
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "azure"  # enables enforcement of Kubernetes NetworkPolicy resources
  }
}
```

## Remediation steps
1. Set `network_profile.network_policy` to `"azure"` (native Azure Network Policy Manager) or `"calico"` on the `azurerm_kubernetes_cluster` resource.
2. Note: `network_policy` can only be set at cluster creation time — enabling it on an existing cluster requires recreating the cluster (Terraform will need to replace the resource), so plan for a maintenance window/migration.
3. `network_policy = "calico"` supports both Azure CNI and kubenet network plugins and additionally supports Windows node pools in newer AKS versions; `"azure"` requires the Azure CNI plugin (`network_plugin = "azure"`).
4. After enabling the policy engine, author actual `NetworkPolicy` Kubernetes resources (a default-deny policy per namespace, then explicit allow rules) — enabling the engine alone does not restrict traffic without policies defined.
5. Test connectivity between all expected communicating services after rolling out default-deny policies, since it's easy to inadvertently break legitimate service-to-service or DNS traffic.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AKSNetworkPolicy.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNetworkPolicy.py)
- [Azure docs: Secure traffic between pods using network policies in AKS](https://learn.microsoft.com/en-us/azure/aks/use-network-policies)
