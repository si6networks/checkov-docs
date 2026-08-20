# CKV_AZURE_141: Ensure AKS local admin account is disabled
## Severity
**LOW** (score: 2.0/10)

An enabled AKS local admin account provides a static-credential, non-AAD administrative path into the cluster that bypasses Kubernetes RBAC and Azure AD conditional access, giving an attacker with the kubeconfig full cluster-admin control.

## Summary
This check ensures an Azure Kubernetes Service (AKS) cluster has local Kubernetes admin accounts disabled, forcing cluster authentication through Azure AD instead of the static `clusterAdmin`/`clusterUser` kubeconfig credentials.

## Applicability
- **ARM**: `Microsoft.ContainerService/managedClusters` resources, property `properties/disableLocalAccounts`.
- **Terraform**: `azurerm_kubernetes_cluster` resource, attribute `local_account_disabled`.
- **Bicep**: compiles to the same ARM resource type.

## Why it matters
By default, AKS clusters (even those with Azure AD integration enabled) retain a local admin account whose kubeconfig can be retrieved via `az aks get-credentials --admin`. This account uses a static, non-expiring client certificate rather than an Azure AD identity, meaning it bypasses Azure AD Conditional Access, MFA, and per-user audit logging entirely. Anyone who obtains this admin kubeconfig — through a leaked file, an overly permissive `Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action` RBAC grant, or a compromised CI/CD pipeline — gets full unaudited cluster-admin access to the Kubernetes API, able to read all secrets, deploy arbitrary workloads, and pivot to anything the cluster's service accounts/managed identities can reach. Disabling local accounts removes this bypass entirely, forcing every kubectl session to authenticate via Azure AD and be subject to Kubernetes RBAC bound to AD identities/groups — enabling proper audit trails and revocation via AD.

## How Checkov evaluates this
Both variants are `BaseResourceValueCheck`s inspecting a single boolean:
- **ARM**: `properties/disableLocalAccounts`, expected value `True` to PASS.
- **Terraform**: `local_account_disabled`, expected value `True` to PASS.
Absent or `false` FAILS (default AKS behavior keeps local accounts enabled).

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

  azure_active_directory_role_based_access_control {
    azure_rbac_enabled = true
  }
  # local_account_disabled left at default (false) -- FAILS, admin bypass still available
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

  azure_active_directory_role_based_access_control {
    azure_rbac_enabled = true
  }

  local_account_disabled = true  # removes the static local admin bypass
}
```

## Remediation steps
1. Set `local_account_disabled = true` (Terraform) or `properties.disableLocalAccounts: true` (ARM/Bicep).
2. This requires Azure AD integration (`azure_active_directory_role_based_access_control` block) to be configured first — Azure AD becomes the only authentication path once local accounts are disabled, so verify AAD-based `kubectl` access works before rolling this out.
3. Assign appropriate Kubernetes RBAC role bindings to Azure AD users/groups/service principals (or use Azure RBAC for Kubernetes Authorization if `azure_rbac_enabled = true`) so legitimate operators retain necessary access.
4. Update any automation (CI/CD deployment pipelines, break-glass scripts) that currently uses `az aks get-credentials --admin` or a stored local-admin kubeconfig — these will stop working and must switch to an Azure AD-authenticated identity (e.g. a service principal/managed identity with an appropriate cluster role binding).
5. Retain a documented, Azure AD-based break-glass access procedure, since the traditional local-admin break-glass path is removed.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AKSLocalAdminDisabled.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSLocalAdminDisabled.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/aks/manage-local-accounts-managed-azure-ad
