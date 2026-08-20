# CKV_AZURE_5: Ensure RBAC is enabled on AKS clusters

## Severity
**MEDIUM** (score: 5.0/10)

Without Kubernetes RBAC enabled, AKS falls back to coarse, overly permissive authorization, undermining the principle of least privilege for workloads and users operating in the cluster.

## Summary
This check verifies that an Azure Kubernetes Service (AKS) cluster has Kubernetes Role-Based Access Control (RBAC) enabled, rather than relying on legacy or absent authorization models.

## Applicability
- **Terraform**: `azurerm_kubernetes_cluster`
- **ARM templates**: `Microsoft.ContainerService/managedClusters`
- **Bicep**: `Microsoft.ContainerService/managedClusters`

## Why it matters
Kubernetes RBAC is the primary mechanism for enforcing least-privilege access within a cluster — controlling which users, groups, and service accounts can read, create, modify, or delete which API resources (pods, secrets, deployments, RBAC objects themselves, etc.). Without RBAC enabled, an AKS cluster may fall back to legacy or permissive authorization behavior, where any authenticated identity effectively has broad access to cluster resources. In a multi-tenant or shared cluster, this means a compromised or overly broad credential (a leaked kubeconfig, a compromised CI/CD pipeline identity, or a misconfigured pod-level token) can be used to read Secrets, escalate privileges by creating privileged pods, or tamper with other tenants' workloads, with no fine-grained authorization boundary stopping it. RBAC is a prerequisite for implementing least privilege and is required by essentially every Kubernetes security hardening guide (CIS Kubernetes Benchmark, NSA/CISA Kubernetes Hardening Guide).

## How Checkov evaluates this
- **ARM**: FAILS immediately if `apiVersion == "2017-08-31"` (that API version has no `enableRBAC` property at all). Otherwise reads `properties.enableRBAC`; PASSES only if it is (case-insensitively) `"true"`.
- **Terraform**: Handles both older and newer provider schema shapes. It checks two possible paths: `role_based_access_control[0].enabled` (older `azurerm` provider, < ~2.99.0) and `role_based_access_control_enabled` (newer provider, >= ~2.99.0). Whichever path is present, PASSES if that boolean is truthy, FAILS if it is explicitly false. If neither key is present at all, the check PASSES — because in current AKS/provider versions RBAC is enabled by default when unspecified.

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  role_based_access_control_enabled = false
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
    node_count = 2
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  role_based_access_control_enabled = true
}
```

## Remediation steps
1. Set `role_based_access_control_enabled = true` on the `azurerm_kubernetes_cluster` resource (current provider), or the older nested `role_based_access_control { enabled = true }` block on legacy provider versions.
2. In ARM/Bicep, set `properties.enableRBAC = true`.
3. **Caveat**: RBAC mode generally cannot be toggled on an existing running AKS cluster without recreating it in some provider/API versions — check `terraform plan` for a forces-replacement warning, and plan for cluster recreation/migration if needed.
4. After enabling RBAC, define `Role`/`ClusterRole` and `RoleBinding`/`ClusterRoleBinding` objects (or use Azure AD integration with Azure RBAC for Kubernetes Authorization) to actually implement least-privilege access — enabling the feature alone doesn't restrict anything without accompanying role definitions.
5. Consider pairing this with Azure AD-integrated RBAC (`azure_active_directory_role_based_access_control` block) for centralized identity management instead of local Kubernetes RBAC subjects alone.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AKSRbacEnabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSRbacEnabled.py)
- [Azure AKS access and identity documentation](https://learn.microsoft.com/en-us/azure/aks/concepts-identity)
