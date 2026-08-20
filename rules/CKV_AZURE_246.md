# CKV_AZURE_246: Ensure Azure AKS cluster HTTP application routing is disabled

## Severity
**MEDIUM** (score: 5.5/10)

Enabling HTTP application routing auto-provisions a public DNS zone and ingress controller for the AKS cluster, expanding the externally-reachable attack surface without necessarily exposing credentials or admin interfaces.

## Summary
This check ensures that the AKS "HTTP application routing" add-on, which automatically creates a public DNS zone and ingress controller for the cluster, is not enabled.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `azurerm_kubernetes_cluster`

## Why it matters
HTTP application routing is a convenience add-on intended for testing/demo purposes. When enabled, AKS automatically provisions an NGINX ingress controller and a publicly resolvable Azure-managed DNS zone, and creates DNS records for any Ingress resource with the routing annotation — with no additional review or approval step. This means any workload deployed to the cluster can silently expose itself to the internet under an Azure-owned DNS domain, undermining network egress/ingress controls and making it hard to track what is externally reachable. Microsoft explicitly does not recommend this add-on for production clusters; production ingress should be deployed and managed deliberately (e.g., NGINX/AGIC ingress controller with its own DNS and TLS lifecycle under your control).

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the `http_application_routing_enabled` attribute:
- **FAIL** if `http_application_routing_enabled = true`.
- **PASS** if it is `false`, unset (defaults to disabled), or any other value.

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  http_application_routing_enabled = true

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

## Remediated example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  http_application_routing_enabled = false   # was true

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
1. Set `http_application_routing_enabled = false` (or remove the attribute so it defaults to disabled).
2. Deploy a purpose-built ingress controller instead (e.g., `ingress-nginx` Helm chart, or Application Gateway Ingress Controller (AGIC)) with explicit TLS certificates and DNS records you manage.
3. Register any required DNS names in your own DNS zone under your organization's domain rather than relying on the AKS-managed `*.<region>.aksapp.io` zone.
4. If this add-on is currently enabled on a live cluster, disabling it removes the automatically created ingress controller and DNS zone — update any Ingress resources that depend on the `addon-http-application-routing` class before disabling.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KubernetesClusterHTTPApplicationRouting.py)
- [AKS HTTP application routing add-on](https://learn.microsoft.com/en-us/azure/aks/http-application-routing)
