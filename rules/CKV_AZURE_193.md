# CKV_AZURE_193: Ensure public network access is disabled for Azure Event Grid Topic

## Severity
**CRITICAL** (score: 9.0/10)

Allowing public network access to an Event Grid Topic exposes the event ingestion endpoint to the internet, enabling unauthorized publication or interception of event data if paired with weak authentication.

## Summary
This check ensures an Azure Event Grid Topic disables public network access, restricting publish/subscribe traffic to private network paths.

## Applicability
- **Frameworks:** Terraform (`azurerm` provider), ARM templates, Bicep (compiled to ARM)
- **Resource types:**
  - ARM: `Microsoft.EventGrid/topics`
  - Terraform: `azurerm_eventgrid_topic`

## Why it matters
When an Event Grid Topic's public network access is enabled, its publishing endpoint is reachable from any internet address, subject only to the topic's authentication configuration (access keys or Azure AD). This expands the attack surface: it exposes the endpoint to internet-wide credential-stuffing/brute-force attempts against access keys, and removes network-layer containment that would otherwise limit exposure to a trusted VNet even if authentication is later misconfigured or a credential leaks. For topics carrying operationally significant events (e.g. triggering downstream automation, security alerting pipelines, or business workflows), an attacker able to reach the endpoint and forge valid credentials could inject malicious events from anywhere in the world. Disabling public access and requiring Private Endpoint connectivity confines both publish and management operations to the trusted network, providing critical defense-in-depth beyond authentication alone.

## How Checkov evaluates this
**ARM:** Checks `properties.publicNetworkAccess` on `Microsoft.EventGrid/topics`, expecting the value `"Disabled"`. Any other value (including the default `"Enabled"`) or a missing field FAILS.

**Terraform:** Checks `public_network_access_enabled` on `azurerm_eventgrid_topic`, expecting `false`. If `true` or unset (Azure's default is enabled), the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_eventgrid_topic" "example" {
  name                           = "example-topic"
  location                       = azurerm_resource_group.example.location
  resource_group_name            = azurerm_resource_group.example.name
  public_network_access_enabled  = true
}
```

## Remediated example
```hcl
resource "azurerm_eventgrid_topic" "example" {
  name                            = "example-topic"
  location                        = azurerm_resource_group.example.location
  resource_group_name             = azurerm_resource_group.example.name
  public_network_access_enabled   = false
}

resource "azurerm_private_endpoint" "example" {
  name                = "example-topic-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                            = "example-topic-privateserviceconnection"
    private_connection_resource_id  = azurerm_eventgrid_topic.example.id
    subresource_names               = ["topic"]
    is_manual_connection            = false
  }
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` on the `azurerm_eventgrid_topic` resource (`properties.publicNetworkAccess: "Disabled"` in ARM/Bicep).
2. Provision an `azurerm_private_endpoint` targeting the topic's `topic` subresource so publishers and management operations from within the VNet retain connectivity.
3. Configure private DNS zone integration (`privatelink.eventgrid.azure.net`) so clients resolve the topic's private endpoint IP.
4. If specific public sources must remain, consider `inbound_ip_rule` (IP allow-listing) as an interim measure, but full disablement plus Private Link is the stronger control.
5. Confirm all publishers can reach the topic via the private path (VNet, peered VNet, or VPN/ExpressRoute) before disabling public access, since this is a breaking change for any external/internet-based publisher.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/EventgridTopicNetworkAccess.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventgridTopicNetworkAccess.py
- [Azure Event Grid network security documentation](https://learn.microsoft.com/en-us/azure/event-grid/network-security)
