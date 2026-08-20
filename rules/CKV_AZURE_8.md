# CKV_AZURE_8: Ensure Kubernetes Dashboard is disabled

## Severity
**HIGH** (score: 8.0/10)

The legacy Kubernetes Dashboard has a documented history of privilege-escalation vulnerabilities and often runs with elevated cluster permissions, so leaving it enabled meaningfully expands the AKS attack surface.

## Summary
This check ensures the deprecated Kubernetes Dashboard add-on is disabled on Azure Kubernetes Service (AKS) clusters.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_kubernetes_cluster`
- **ARM/Bicep**: `Microsoft.ContainerService/managedClusters`

## Why it matters
The Kubernetes Dashboard is a web-based UI historically bundled with Kubernetes clusters that provides broad visibility into, and control over, cluster workloads, secrets, and configuration. It has a well-documented history of severe misconfiguration risk: several widely publicized breaches (including a notable Tesla cloud-crypto-mining incident) resulted from Dashboards left reachable without authentication, giving attackers direct access to cluster secrets, the ability to deploy pods, and a path to full cluster compromise. Microsoft deprecated and removed the AKS-managed Dashboard add-on because of these risks, and any cluster built on the old `2017-08-31` API version had no way to disable it at all. A cluster with the dashboard enabled — or built on an API version that can't turn it off — presents an unnecessary, historically high-risk attack surface for lateral movement inside the cluster.

## How Checkov evaluates this
- **ARM**: Fails immediately if `apiVersion` is `2017-08-31` (that version has no `addonProfiles` option to disable the dashboard, so it cannot be considered safe). Otherwise, it requires `properties.addonProfiles.kubeDashboard` to exist as a dict and its `enabled` field to be the string `"false"` (case-insensitive) to pass; any other combination (missing `addonProfiles`, missing `kubeDashboard`, or `enabled` not equal to false) fails.
- **Terraform**: Looks at `addon_profile[0].kube_dashboard[0].enabled`. If that value is truthy, it fails. If the block/attribute is absent, or `enabled` is falsy, it passes.

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

  addon_profile {
    kube_dashboard {
      enabled = true   # exposes the deprecated, high-risk Kubernetes Dashboard
    }
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
    name       = "default"
    node_count = 2
    vm_size    = "Standard_DS2_v2"
  }

  addon_profile {
    kube_dashboard {
      enabled = false   # Kubernetes Dashboard disabled
    }
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Set `kube_dashboard.enabled = false`, or remove the `kube_dashboard`/`addon_profile` block entirely (the addon has been fully removed from current AKS API versions, so newer clusters won't have this add-on at all).
2. If on a legacy ARM template pinned to `apiVersion 2017-08-31`, upgrade to a current API version that supports `addonProfiles`, since that old version cannot pass this check under any configuration.
3. For visibility/administration needs previously served by the Dashboard, use `kubectl` with Azure AD-integrated RBAC, or the Azure Portal's built-in Kubernetes resources view.
4. Changing this setting does not require cluster replacement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSDashboardDisabled.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AKSDashboardDisabled.py
- Azure docs: https://learn.microsoft.com/en-us/azure/aks/kubernetes-dashboard
