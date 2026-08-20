# CKV_AZURE_222: Ensure that Azure Web App public network access is disabled
## Severity
**HIGH** (score: 7.5/10)

A Web App reachable from the public internet exposes the application (and often its management endpoints) to broad, untrusted network access instead of being restricted to private/VNet-integrated paths.

## Summary
Ensures that Azure App Service Web Apps are not reachable directly from the public internet, requiring access via private networking instead.

## Applicability
- **Terraform**: `azurerm_linux_web_app`, `azurerm_windows_web_app` — inspects `public_network_access_enabled`
- **ARM**: `Microsoft.Web/sites`, `Microsoft.Web/sites/slots`, `Microsoft.Web/sites/config` — inspects `properties.publicNetworkAccess`
- **Bicep**: compiles to the ARM resource types above

## Why it matters
When an App Service's public network access is enabled (the default), the web app's public hostname (`*.azurewebsites.net` or a custom domain) is reachable from any address on the internet, regardless of any VNet integration or private endpoint you may have also configured — those additional network controls only add a *private* path in, they don't remove the *public* one unless public access is explicitly disabled. This leaves internet-facing exposure of the application's full HTTP surface, including any administrative endpoints, debug/diagnostics routes, or backend APIs that were only intended for internal consumption, to internet-wide scanning and attack attempts (credential stuffing, exploitation of framework/CVE vulnerabilities, DoS traffic) independent of the app's own authentication logic. For apps meant to be consumed only through an internal network, a VPN, an internal load balancer, or via Azure Front Door/Application Gateway with private connectivity, leaving public access on defeats the purpose of that network segmentation and widens the blast radius of any single vulnerability in the app itself.

## How Checkov evaluates this
- **Terraform**: inspects `public_network_access_enabled`. Expected value is `False`. **PASSES** only when explicitly set to `false`; **FAILS** if `true` or left unset (default is `true`).
- **ARM**: inspects `properties.publicNetworkAccess`. Expected value is the string `"Disabled"`. **PASSES** only when this equals `"Disabled"`; **FAILS** otherwise (including the default `"Enabled"` or if unset).

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  # public_network_access_enabled left unset -> defaults to true (public)
  site_config {}
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  public_network_access_enabled = false   # deny direct internet access

  site_config {}
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess: "Disabled"` (ARM/Bicep) on the Web App and any deployment slots.
2. Before disabling public access, ensure a private path already exists — provision a private endpoint (`azurerm_private_endpoint`) targeting the site's `sites` sub-resource, and/or configure VNet integration for outbound traffic, so the app remains reachable to your internal users/services.
3. Reconfigure DNS (private DNS zone linked to your VNet) so internal clients resolve the app's hostname to the private endpoint's private IP rather than the public IP.
4. Update any external integrations (webhooks, third-party callbacks, CDN origins) that currently depend on public reachability — they'll need to be re-routed through an approved private/hybrid path (e.g., Azure Front Door Premium with Private Link origin) if public access is disabled entirely.
5. Test both the management/SCM endpoint (Kudu) and the main app endpoint after the change, since both are affected by this setting and both may be needed for CI/CD deployment access.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServicePublicAccessDisabled.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServicePublicAccessDisabled.py
- Azure docs: https://learn.microsoft.com/en-us/azure/app-service/networking/private-endpoint
