# CKV_AZURE_116: Ensure that AKS uses Azure Policies Add-on
## Severity
**LOW** (score: 2.0/10)

Missing the Azure Policy add-on removes a centralized guardrail for enforcing in-cluster security posture, which is a control-plane governance gap rather than a directly exploitable vulnerability.

## Summary
This check verifies that an Azure Kubernetes Service (AKS) cluster has the Azure Policy Add-on enabled, allowing Azure Policy to enforce and audit configuration compliance across the cluster's Kubernetes resources.

## Applicability
- **IaC framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_kubernetes_cluster`

## Why it matters
Without Azure Policy integration, AKS clusters have no centralized, declarative guardrail mechanism preventing developers from deploying non-compliant workloads — e.g. privileged containers, containers running as root, pods without resource limits, images from untrusted registries, or hostPath volume mounts. Azure Policy for AKS (built on Gatekeeper/OPA) lets an organization define and enforce these guardrails at admission time, and gives auditors/compliance teams a single pane of glass across many clusters (e.g. for CIS Kubernetes Benchmark or PCI-DSS attestations) instead of relying on each team's local RBAC and admission controller configuration. Absence of this control means policy drift is undetectable until an incident (e.g. a workload with hostNetwork access) has already occurred.

## How Checkov evaluates this
The check inspects the AKS resource for either of two configuration shapes, reflecting an Azure provider syntax change:
- **Modern syntax (Azure provider ≥ v2.97.0):** PASS if the top-level `azure_policy_enabled` attribute is truthy.
- **Legacy syntax (Azure provider ≤ v2.96.0):** PASS if `addon_profile[0].azure_policy[0].enabled` is truthy.
- **FAIL** in all other cases (attribute absent, set to `false`, or nested blocks missing/malformed).

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
  # azure_policy_enabled not set -> no policy enforcement on the cluster
}
```

## Remediated example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "aks-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "aksexample"

  azure_policy_enabled = true  # enables the Azure Policy Add-on (Gatekeeper)

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
1. Add `azure_policy_enabled = true` to the `azurerm_kubernetes_cluster` resource (recommended for Azure provider v2.97.0+).
2. If pinned to an older `azurerm` provider version, instead set the nested block: `addon_profile { azure_policy { enabled = true } }`.
3. After enabling, assign the built-in "Kubernetes cluster pod security restricted standards" (or your org's custom) Azure Policy initiative to the cluster's scope so the add-on actually has policies to enforce.
4. Test policies in `audit` effect first in non-production before switching to `deny` to avoid unexpectedly blocking legitimate deployments.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSUsesAzurePoliciesAddon.py)
- [Azure Policy for Kubernetes documentation](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/policy-for-kubernetes)
