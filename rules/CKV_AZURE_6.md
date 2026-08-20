# CKV_AZURE_6: Ensure AKS has an API Server Authorized IP Ranges enabled
## Severity
**LOW** (score: 2.0/10)

Leaving the AKS API server reachable from any source IP exposes the cluster's most powerful control point to internet-wide credential-stuffing and vulnerability exploitation attempts, with authentication as the only remaining safeguard.

## Summary
This check fails when an Azure Kubernetes Service (AKS) cluster's Kubernetes API server does not have an authorized IP range restriction configured, meaning the cluster's control-plane API is reachable from any IP address on the internet.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

Applies to Terraform (`azurerm_kubernetes_cluster`), ARM templates, and Bicep, for the resource type `Microsoft.ContainerService/managedClusters`.

## Why it matters
The Kubernetes API server is the single most powerful control point in a cluster — anyone who can reach it and authenticate can create/modify workloads, read secrets, and potentially escalate to full cluster (and sometimes underlying node/cloud) compromise. Leaving the API server open to all source IPs means the only defense against unauthorized access is authentication/authorization (kubeconfig credentials, Azure AD RBAC), so a single leaked kubeconfig, stolen service account token, or exploited authentication bypass becomes immediately exploitable from anywhere on the internet. Restricting authorized IP ranges to known corporate egress IPs, CI/CD runners, or VPN endpoints adds a network-layer control that limits exposure even if credentials are compromised, and it also reduces the attack surface for API-server-targeting vulnerabilities and brute-force/credential-stuffing attempts.

## How Checkov evaluates this
- ARM: behavior differs by `apiVersion`. Versions `2017-08-31`/`2018-03-31` always FAIL (no such feature existed). Versions `2019-02-01`/`2019-04-01`/`2019-06-01` (preview support) PASS only if `properties.apiServerAuthorizedIPRanges` is present and non-empty. For `2019-08-01` and later, it looks for `properties.apiServerAccessProfile.authorizedIPRanges` and PASSES only if that list is non-empty.
- Terraform: PASSES automatically if `private_cluster_enabled = true` (authorized IP ranges don't apply to private clusters). Otherwise checks the legacy `api_server_authorized_ip_ranges` attribute (provider ≤3.38.0) for a non-empty first value, and falls back to checking `api_server_access_profile[0].authorized_ip_ranges[0]` is set to any non-empty value (`ANY_VALUE`). If neither is populated and the cluster isn't private, it FAILS.

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

  # no api_server_access_profile — API server open to all IPs, not a private cluster
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

  api_server_access_profile {
    authorized_ip_ranges = ["203.0.113.0/24"]  # restrict API server access
  }
}
```

## Remediation steps
1. Add an `api_server_access_profile` block with `authorized_ip_ranges` populated with your organization's known egress CIDR ranges (office IPs, VPN gateways, CI/CD runner IPs).
2. Alternatively, for maximum isolation, set `private_cluster_enabled = true` to make the API server only reachable via a private endpoint within the VNet (mutually exclusive with authorized IP ranges, and this check treats private clusters as compliant).
3. When restricting IP ranges, always include the IP ranges used by Azure DevOps/GitHub Actions-hosted runners or any managed CI/CD system if pipelines need `kubectl` access, or use self-hosted runners inside the VNet instead.
4. Note this setting can be updated in-place on most AKS clusters without recreation, but converting between public and private cluster modes may require additional steps.
5. Keep the authorized IP range list current — stale ranges (e.g. from a decommissioned office) create false confidence of restriction while offering no protection.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AKSApiServerAuthorizedIpRanges.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSApiServerAuthorizedIpRanges.py)
- [Azure docs: Secure access to the API server using authorized IP address ranges](https://learn.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges)
