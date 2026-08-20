# CKV_AZURE_217: Ensure Azure Application gateways listener that allow connection requests over HTTP
## Severity
**HIGH** (score: 7.5/10)

An Application Gateway listener accepting HTTP allows client traffic to traverse the network unencrypted, enabling credential and data interception via man-in-the-middle attacks.

## Summary
Ensures that Azure Application Gateway HTTP listeners are configured to use the `Https` protocol instead of plain `Http`, so client connections to the gateway are encrypted in transit.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_application_gateway` — inspects `http_listener[0].protocol`

## Why it matters
Application Gateway listeners define the front-end entry point that receives client traffic. If a listener's protocol is set to `Http` rather than `Https`, all traffic between the client (potentially over the public internet) and the gateway is transmitted in cleartext. This exposes request bodies, cookies, session tokens, authentication headers, and any other sensitive data submitted by users to interception by anyone able to observe the network path — a classic man-in-the-middle risk. It also fails to protect against downgrade or spoofing attacks and generally violates baseline compliance requirements (PCI-DSS, HIPAA, SOC 2, etc.) that mandate encryption of data in transit for any service handling sensitive user data. Even for gateways intended purely as internal load balancers, cleartext traffic within a VNet is still visible to any compromised host or malicious insider with network access to that segment.

## How Checkov evaluates this
The check inspects `http_listener/[0]/protocol`. The expected value is the string `"Https"`. The check **PASSES** only if the listener's `protocol` attribute equals `"Https"`; it **FAILS** if the protocol is `"Http"` or any other/missing value.

## Non-compliant example
```hcl
resource "azurerm_application_gateway" "example" {
  name                = "example-appgw"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  # ... gateway_ip_configuration, frontend_port, frontend_ip_configuration, backend_address_pool, etc. omitted ...

  http_listener {
    name                           = "example-listener"
    frontend_ip_configuration_name = "example-frontend-ip"
    frontend_port_name             = "example-frontend-port"
    protocol                       = "Http"
  }
}
```

## Remediated example
```hcl
resource "azurerm_application_gateway" "example" {
  name                = "example-appgw"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  # ... gateway_ip_configuration, frontend_port, frontend_ip_configuration, backend_address_pool, etc. omitted ...

  http_listener {
    name                           = "example-listener"
    frontend_ip_configuration_name = "example-frontend-ip"
    frontend_port_name             = "example-frontend-port"
    protocol                       = "Https"          # encrypted listener
    ssl_certificate_name           = "example-cert"    # required for Https listeners
  }
}
```

## Remediation steps
1. Change the listener's `protocol` to `"Https"`.
2. Provision a TLS certificate for the listener — either reference an `ssl_certificate` block on the gateway (`ssl_certificate_name`) sourced from a PFX/Key Vault, or use `ssl_certificate_key_vault_secret_id` for Key Vault-integrated certificates.
3. Update the frontend port used by the listener to the HTTPS port (typically 443) if it was previously bound to port 80.
4. If you must keep a port-80 listener for user convenience, configure it only to perform an HTTP-to-HTTPS redirect (via `redirect_configuration` with `redirect_type = "Permanent"`) rather than serving application traffic directly over HTTP.
5. Update DNS/client configuration and test connectivity after the change, since browsers/clients hitting the old HTTP endpoint directly (without a redirect) will now fail.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppGWUsesHttps.py
- Azure docs: https://learn.microsoft.com/en-us/azure/application-gateway/redirect-http-to-https-portal
