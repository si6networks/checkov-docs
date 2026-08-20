# CKV_AZURE_185: Ensure 'Public Access' is not Enabled for App configuration

## Severity
**CRITICAL** (score: 9.0/10)

Enabling public network access on Azure App Configuration exposes an internet-reachable management/data endpoint that frequently stores application secrets and connection strings, making it a prime target for unauthorized data exfiltration or takeover.

## Summary
This check ensures Azure App Configuration stores do not have their `public_network_access` setting explicitly set to `Enabled`, so that access is restricted to private/network-controlled paths.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (`azurerm` provider)
- **Resource type:** `azurerm_app_configuration`

## Why it matters
Azure App Configuration stores often hold application settings, feature flags, and (in some designs) connection strings or other operationally sensitive values. When public network access is enabled, the store's data-plane endpoint is reachable from any internet address (subject to authentication), expanding the attack surface: it becomes a target for credential-stuffing/brute force against access keys, exposed to any future authentication misconfiguration, and outside the reach of network-layer controls like NSGs, firewalls, or Private Link policies that security teams rely on to contain blast radius. Disabling public access and requiring Private Endpoint connectivity confines traffic to the trusted virtual network, so even a leaked credential can't be used from an arbitrary internet host — a significant defense-in-depth improvement.

## How Checkov evaluates this
This is a negative-value check on the `public_network_access` attribute. If the value is the string `"Enabled"`, the check FAILS. Any other value (e.g. `"Disabled"`), or the attribute being unset (default behavior — no `missing_attribute_result` override, meaning missing attribute is treated as passing since it's not in the forbidden list), PASSES.

## Non-compliant example
```hcl
resource "azurerm_app_configuration" "example" {
  name                       = "appconf1"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  sku                        = "standard"
  public_network_access      = "Enabled"
}
```

## Remediated example
```hcl
resource "azurerm_app_configuration" "example" {
  name                       = "appconf1"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  sku                        = "standard"
  public_network_access      = "Disabled"
}

resource "azurerm_private_endpoint" "example" {
  name                = "appconf1-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "appconf1-privateserviceconnection"
    private_connection_resource_id = azurerm_app_configuration.example.id
    subresource_names              = ["configurationStores"]
    is_manual_connection           = false
  }
}
```

## Remediation steps
1. Set `public_network_access = "Disabled"` on the `azurerm_app_configuration` resource (requires the `standard` SKU — the `free` SKU does not support Private Link/disabling public access).
2. Provision an `azurerm_private_endpoint` targeting the App Configuration store's `configurationStores` subresource so applications inside the VNet can still reach it.
3. Update DNS so consuming applications resolve the store's private endpoint IP (typically via an `azurerm_private_dns_zone` linked to the VNet).
4. Verify no external CI/CD systems or third-party integrations depend on public reachability before disabling; they will need to run from within the VNet, via VPN/ExpressRoute, or via a jump host/self-hosted agent afterward.
5. This change can be applied in place but effectively cuts off public connectivity immediately — coordinate a maintenance window and confirm private endpoint connectivity works before disabling public access, to avoid an outage.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppConfigPublicAccess.py
- [Azure App Configuration Private Link documentation](https://learn.microsoft.com/en-us/azure/azure-app-configuration/concept-private-endpoint)
