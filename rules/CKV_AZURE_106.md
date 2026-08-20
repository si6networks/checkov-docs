# CKV_AZURE_106: Ensure that Azure Event Grid Domain public network access is disabled
## Severity
**HIGH** (score: 7.0/10)

Public network access to an Event Grid Domain allows untrusted network paths to publish or subscribe to events, potentially enabling unauthorized data injection or interception of event traffic.

## Summary
This check ensures that an Azure Event Grid Domain resource disables public network access, restricting event ingestion/management to private network paths.

## Applicability
- **Terraform**: `azurerm_eventgrid_domain` (inspects `public_network_access_enabled`)
- (No ARM/Bicep implementation reported for this specific check.)

## Why it matters
An Event Grid Domain acts as a management/routing endpoint for large numbers of topics and event subscriptions, often integrating with internal automation, security tooling, and application event pipelines. If public network access is left enabled, the domain's endpoint is reachable from the internet, allowing anyone who obtains (or guesses/leaks) an access key or SAS token to publish or manage events without needing network-level access to your VNet. This can enable event injection attacks (flooding downstream subscribers with malicious or malformed events), denial-of-service on event-driven workflows, or reconnaissance of your event schema/topics. Disabling public network access and using Private Link ensures that even a leaked key cannot be used unless the attacker already has a foothold inside the private network.

## How Checkov evaluates this
The check inspects the `public_network_access_enabled` attribute on `azurerm_eventgrid_domain`. It expects this to be `false`; if it is `true` (the provider default) or the attribute is omitted, the check **FAILS**. Setting it explicitly to `false` **PASSES**.

## Non-compliant example
```hcl
resource "azurerm_eventgrid_domain" "bad_example" {
  name                = "bad-eventgrid-domain"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  public_network_access_enabled = true
}
```

## Remediated example
```hcl
resource "azurerm_eventgrid_domain" "good_example" {
  name                = "good-eventgrid-domain"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  # Fix: disable public network access; require private endpoint connectivity
  public_network_access_enabled = false
}

resource "azurerm_private_endpoint" "eventgrid_pe" {
  name                = "eventgrid-domain-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "eventgrid-privatelink"
    private_connection_resource_id = azurerm_eventgrid_domain.good_example.id
    subresource_names              = ["domain"]
    is_manual_connection           = false
  }
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` on the `azurerm_eventgrid_domain` resource.
2. Provision a Private Endpoint for the `domain` sub-resource so publishers/subscribers inside the VNet can still reach the domain.
3. If specific external partners must publish events, consider `inbound_ip_rule` (IP allow-listing) only as an interim/limited mitigation — it is weaker than disabling public access entirely.
4. Update publisher application configuration/DNS to route through the private endpoint.
5. Validate all event publishers and event subscription webhook endpoints continue to function after the change, since this can break connectivity for clients outside the VNet.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventgridDomainNetworkAccess.py)
- [Azure docs: Event Grid Private Link](https://learn.microsoft.com/en-us/azure/event-grid/network-security)
