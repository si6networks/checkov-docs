# CKV_AZURE_204: Ensure 'public network access enabled' is set to 'False' for Azure Service Bus

## Severity
**HIGH** (score: 7.5/10)

Enabling public network access exposes the Service Bus namespace's endpoint to the entire internet, subjecting its authentication layer to internet-wide scanning and credential-stuffing attempts that would otherwise be blocked at the network boundary.

## Summary
This check ensures an Azure Service Bus namespace has `public_network_access_enabled` set to `false`, requiring access through private endpoints/networks rather than the public internet.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `azurerm_servicebus_namespace`

## Why it matters
When public network access is enabled, the Service Bus namespace's endpoint is reachable from anywhere on the internet (subject to any IP firewall rules configured separately). This significantly expands the attack surface: it exposes the authentication layer directly to internet-wide scanning and brute-force/credential-stuffing attempts against SAS keys or Azure AD tokens, and any misconfiguration in network rules or a bug in access control becomes internet-exploitable rather than confined to a private network boundary. Disabling public network access and instead using Azure Private Link/Private Endpoint ensures traffic to the namespace stays on the Microsoft backbone network or the organization's private network, removing exposure to the open internet entirely and mitigating risks like DNS hijacking or IP spoofing based attacks against a public endpoint.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `public_network_access_enabled`
- **Expected value:** `False`
- The check FAILS if `public_network_access_enabled` is `true` or left at its default (`true` in the `azurerm` provider), and PASSES only when explicitly set to `false`.

## Non-compliant example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Premium"

  public_network_access_enabled = true
}
```

## Remediated example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Premium"

  public_network_access_enabled = false   # namespace only reachable via private endpoint/network

  network_rule_set {
    default_action = "Deny"
  }
}

resource "azurerm_private_endpoint" "example" {
  name                = "example-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "example-privateserviceconnection"
    private_connection_resource_id = azurerm_servicebus_namespace.example.id
    subresource_names               = ["namespace"]
    is_manual_connection             = false
  }
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` on the namespace. Note this requires the `Premium` SKU, since Private Link support for Service Bus is a Premium-tier feature.
2. Provision an `azurerm_private_endpoint` for the namespace, connected to the appropriate VNet/subnet, so internal consumers retain connectivity.
3. Configure DNS (Azure Private DNS zone `privatelink.servicebus.windows.net`) so clients resolve the namespace's FQDN to the private endpoint's IP.
4. If some access must remain public temporarily during migration, use `network_rule_set` with specific allowed IP ranges/VNet rules rather than leaving the namespace fully public — but treat that as an interim, not final, state.
5. Test connectivity from every consuming application/service after the change, since this is a breaking change for anything connecting from outside the private network.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusPublicAccessDisabled.py)
- [Azure Service Bus Private Link documentation](https://learn.microsoft.com/en-us/azure/service-bus-messaging/private-link-service)
