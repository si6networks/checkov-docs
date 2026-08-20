# CKV_AZURE_231: Ensure App Service Environment is zone redundant

## Severity
**MEDIUM** (score: 5.0/10)

Missing zone redundancy for App Service Environment affects availability during a zone outage rather than confidentiality or integrity of the hosted application.

## Summary
This check ensures an Azure App Service Environment (v3) is deployed as zone redundant, spreading its underlying instances across multiple Availability Zones.

## Applicability
- **Terraform**: `azurerm_app_service_environment_v3` resources — inspects the `zone_redundant` attribute.

## Why it matters
An App Service Environment (ASE) is a single-tenant, dedicated deployment of the App Service platform, typically used for high-isolation or high-compliance workloads (VNet-injected apps, regulated industries). If an ASE is not zone redundant, all of its instances run in a single Availability Zone. A zone-level outage (power, cooling, or network failure affecting that specific datacenter) takes down every app hosted in that ASE simultaneously — a much larger blast radius than a single VM failing, since an ASE often hosts many App Service plans and apps. Because ASEs are frequently chosen specifically for workloads that require higher assurance and isolation, an availability gap here undermines the very reason the ASE was provisioned instead of shared App Service.

## How Checkov evaluates this
`BaseResourceValueCheck` inspecting the `zone_redundant` attribute on `azurerm_app_service_environment_v3`. The check PASSES only if `zone_redundant` is explicitly `true`; it FAILS if omitted (defaults to `false`) or explicitly set to `false`.

## Non-compliant example
```hcl
resource "azurerm_app_service_environment_v3" "example" {
  name                = "example-ase"
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id
  # zone_redundant not set -> defaults to false, FAILS
}
```

## Remediated example
```hcl
resource "azurerm_app_service_environment_v3" "example" {
  name                = "example-ase"
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id
  zone_redundant      = true   # <-- spans multiple Availability Zones, PASSES
}
```

## Remediation steps
1. Set `zone_redundant = true` on the `azurerm_app_service_environment_v3` resource.
2. Confirm the target Azure region supports Availability Zones (not all regions do) and that the subnet/VNet is provisioned in a region where zone redundancy is supported for ASE v3.
3. Zone redundancy for ASE v3 typically requires a minimum instance count; ensure your App Service plans have enough instances to spread across zones.
4. This setting can generally only be configured at creation time — changing it on an existing ASE may require recreating the environment, so plan for downtime/migration if retrofitting an existing deployment.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceEnvironmentZoneRedundant.py
- Azure docs: https://learn.microsoft.com/en-us/azure/app-service/environment/zone-redundancy
