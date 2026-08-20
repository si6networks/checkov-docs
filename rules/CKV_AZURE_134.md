# CKV_AZURE_134: Ensure that Cognitive Services accounts disable public network access
## Severity
**HIGH** (score: 7.5/10)

Allowing public network access to Cognitive Services accounts exposes an AI/ML service endpoint (and any data sent to it) directly to the internet, broadening the attack surface for credential stuffing, abuse, or data exfiltration.

## Summary
This check ensures an Azure Cognitive Services account (e.g. Azure OpenAI, Computer Vision, Speech, etc.) has public network access explicitly disabled, restricting access to private endpoints/VNets only.

## Applicability
- **ARM**: `Microsoft.CognitiveServices/accounts` resources, property `properties/publicNetworkAccess`.
- **Terraform**: `azurerm_cognitive_account` resource, attribute `public_network_access_enabled`.
- **Bicep**: compiles to the same ARM resource type.

## Why it matters
Cognitive Services accounts often process sensitive data — text, images, audio, or documents sent for AI inference — and typically require API keys or Azure AD tokens for authentication. However, exposing the account's data-plane endpoint to the public internet increases the attack surface: it becomes reachable for credential-stuffing/brute-force attempts against API keys, is more exposed to DDoS, and (particularly relevant for Azure OpenAI-style accounts) increases the blast radius if an API key or token leaks, since an attacker anywhere on the internet — not just inside your VNet — can immediately use it. Disabling public network access and requiring traffic via Azure Private Link/private endpoints or VNet service endpoints ensures inference requests only originate from your controlled network, adding a network-layer control on top of the identity-layer authentication.

## How Checkov evaluates this
Both variants are `BaseResourceValueCheck`s that simply inspect one attribute and expect a specific value:
- **ARM**: inspects `properties/publicNetworkAccess` and expects the string `"Disabled"`. Any other value (including missing, which defaults to enabled) fails.
- **Terraform**: inspects `public_network_access_enabled` and expects it to equal `False`. If omitted, the provider default (`true`) applies and the check fails.

## Non-compliant example
```hcl
resource "azurerm_cognitive_account" "example" {
  name                = "example-cognitive"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  kind                = "TextAnalytics"
  sku_name            = "S0"
  # public_network_access_enabled left at default (true) -- FAILS
}
```

## Remediated example
```hcl
resource "azurerm_cognitive_account" "example" {
  name                = "example-cognitive"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  kind                = "TextAnalytics"
  sku_name            = "S0"

  public_network_access_enabled = false  # forces access via private endpoint / VNet only

  network_acls {
    default_action = "Deny"
  }
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess: "Disabled"` (ARM/Bicep) on the Cognitive Services account.
2. Provision a Private Endpoint (`azurerm_private_endpoint`) connected to the account's `account` sub-resource so internal consumers can still reach it over the private IP.
3. Update any client applications/services calling the Cognitive Services endpoint to resolve via the private DNS zone (`privatelink.cognitiveservices.azure.com` or the service-specific private DNS zone) instead of the public FQDN.
4. If some public access is still required temporarily, use `network_acls` with `ip_rules`/`virtual_network_rules` as an interim compensating control, but plan to migrate to private endpoints for defense in depth.
5. Test connectivity from all consuming networks (VNets, on-prem via ExpressRoute/VPN) before disabling public access in production to avoid an outage.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/CognitiveServicesDisablesPublicNetwork.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CognitiveServicesDisablesPublicNetwork.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/ai-services/cognitive-services-virtual-networks
