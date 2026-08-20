# CKV_AZURE_237: Ensure dedicated data endpoints are enabled

## Severity
**LOW** (score: 2.0/10)

Dedicated data endpoints for ACR reduce network exposure surface for a private registry, but their absence is a defense-in-depth network hardening gap rather than an active exposure by itself.

## Summary
This check ensures an Azure Container Registry has dedicated data endpoints enabled, giving each registry's data (image layers/manifests) its own dedicated hostname per region rather than a shared wildcard endpoint.

## Applicability
- **Terraform**: `azurerm_container_registry` resources — inspects the `data_endpoint_enabled` attribute.

## Why it matters
By default, Azure Container Registry serves blob data (image layers) through a shared wildcard domain (`*.blob.core.windows.net`) used by many registries across the Azure fleet. This makes it impossible to build tight network egress rules — since you cannot allow-list "your registry's data endpoint" specifically without allowing the entire wildcard range, which also permits traffic to every other tenant's registry data on that shared domain. In network environments that enforce strict egress controls (e.g., firewalls with FQDN-based allow-lists, or environments trying to prevent data exfiltration via lookalike registries), this makes it harder to guarantee traffic is only reaching your registry.

Enabling dedicated data endpoints (`data_endpoint_enabled = true`, Premium SKU only) gives the registry unique, per-region hostnames for its data plane. This lets you configure firewall rules that allow-list only your registry's actual data endpoints, closing off a potential path for image-pull traffic to be redirected to, or blended with, other tenants' registry data and enabling more precise network segmentation and monitoring.

## How Checkov evaluates this
`BaseResourceValueCheck` inspecting `data_endpoint_enabled` on `azurerm_container_registry`. The check PASSES only if this is explicitly `true`; it FAILS if omitted or `false`.

## Non-compliant example
```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Premium"
  admin_enabled       = false
  # data_endpoint_enabled not set -> defaults to false, FAILS
}
```

## Remediated example
```hcl
resource "azurerm_container_registry" "example" {
  name                   = "exampleacr"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  sku                    = "Premium"
  admin_enabled          = false
  data_endpoint_enabled  = true   # <-- dedicated per-region data hostname, PASSES
}
```

## Remediation steps
1. Ensure the registry SKU is `Premium` — dedicated data endpoints require this tier.
2. Set `data_endpoint_enabled = true` on the `azurerm_container_registry` resource.
3. Update any network firewall rules, private DNS configurations, or NSG allow-lists that currently reference the shared `*.blob.core.windows.net` wildcard for registry pulls — you'll now need to allow the registry's specific dedicated data endpoint hostnames per enabled region instead.
4. If you use geo-replication, verify dedicated data endpoints are correctly resolvable/allow-listed in every replicated region, not just the primary.
5. Test image pulls thoroughly after enabling this in restrictive network environments, since a missed firewall rule for the new dedicated hostname will break pulls.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRDedicatedDataEndpointEnabled.py
- Azure docs: https://learn.microsoft.com/en-us/azure/container-registry/container-registry-firewall-access-rules#enable-dedicated-data-endpoints
