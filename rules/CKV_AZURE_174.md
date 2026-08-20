# CKV_AZURE_174: Ensure API management public access is disabled

## Severity
**CRITICAL** (score: 9.0/10)

Enabling public network access exposes the APIM gateway and its management/developer portal directly to the internet, bypassing intended private VNet/NSG controls and exposing potentially internal-only APIs to direct internet scanning and attack.

## Summary
This check ensures that an Azure API Management instance does not have public network access enabled, forcing all access through private networking (VNet integration / Private Endpoint).

## Applicability
- **Terraform**: `azurerm_api_management` (`public_network_access_enabled`).
- **ARM/Bicep**: `Microsoft.ApiManagement/service` (`properties.publicNetworkAccess`).

## Why it matters
When public network access is enabled, the APIM gateway (and its management/developer portal endpoints) is reachable directly from the internet, independent of any VNet integration you may have configured elsewhere. This means network-level access controls like NSGs, firewalls, or the intent of a private VNet deployment can be silently bypassed via the public data-plane endpoint, exposing the API surface — and potentially internal-only APIs meant to be reachable only from within a corporate network or via a partner VPN — to direct internet scanning and attack. Disabling public network access ensures the only path to APIM is via approved private connectivity (Private Endpoint or internal VNet mode), closing off an easily-overlooked internet-facing attack surface.

## How Checkov evaluates this
- **Terraform** (`APIManagementPublicAccess`, a negative-value check with `missing_attribute_result=FAILED`): inspects `public_network_access_enabled`. If it is `true`, the check **FAILS**; if `false`, it **PASSES**. If the attribute is missing entirely, it is treated as a **FAIL** (i.e., the check does not trust the provider default silently).
- **ARM**: inspects `properties.publicNetworkAccess` and expects the exact value `"Disabled"`; anything else (including `"Enabled"` or absent) **FAILS**.

## Non-compliant example
```hcl
resource "azurerm_api_management" "apim" {
  name                          = "my-apim"
  location                      = azurerm_resource_group.rg.location
  resource_group_name           = azurerm_resource_group.rg.name
  publisher_name                = "My Company"
  publisher_email               = "admin@example.com"
  sku_name                      = "Premium_1"
  public_network_access_enabled = true
}
```

## Remediated example
```hcl
resource "azurerm_api_management" "apim" {
  name                          = "my-apim"
  location                      = azurerm_resource_group.rg.location
  resource_group_name           = azurerm_resource_group.rg.name
  publisher_name                = "My Company"
  publisher_email               = "admin@example.com"
  sku_name                      = "Premium_1"
  public_network_access_enabled = false

  virtual_network_type = "Internal"
  virtual_network_configuration {
    subnet_id = azurerm_subnet.apim.id
  }
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess = "Disabled"` (ARM/Bicep).
2. Before disabling, ensure private connectivity is already in place — either VNet integration (`virtual_network_type = "Internal"` or `"External"`) or a Private Endpoint — otherwise legitimate clients will lose access entirely.
3. Disabling public access on the Developer/Consumption SKU may not be supported; verify this feature is available on your chosen APIM SKU tier (typically requires Developer, Premium, or supports Private Endpoints depending on tier and Azure's current feature matrix).
4. Update any CI/CD, monitoring, or developer-portal access paths that previously relied on the public endpoint to route through the private network instead (VPN, ExpressRoute, jumpbox, or Private Endpoint DNS).
5. Test thoroughly in a non-production APIM instance first, as this change can be disruptive to existing integrations.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIManagementPublicAccess.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/APIManagementPublicAccess.py
- Microsoft Docs: https://learn.microsoft.com/en-us/azure/api-management/private-endpoint
