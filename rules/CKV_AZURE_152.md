# CKV_AZURE_152: Ensure Client Certificates are enforced for API management

## Severity
**HIGH** (score: 7.0/10)

Failing to enforce client certificates on API Management removes an authentication layer for API callers, allowing unauthenticated or unauthorized clients to reach backend APIs that rely on mTLS for access control.

## Summary
This check ensures that Azure API Management instances on the **Consumption** SKU tier require mutual TLS (client certificate authentication) for incoming requests to the gateway.

## Applicability
- **Framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_api_management`

## Why it matters
API Management gateways are typically internet-facing entry points that route to backend APIs. Without client certificate enforcement, any client that can reach the gateway endpoint can attempt to call the API — authentication then relies entirely on whatever the API itself implements (subscription keys, OAuth, etc.), and misconfigurations further upstream go unmitigated. Requiring client certificates adds a strong, transport-level layer of mutual authentication, meaning a caller must possess a valid, provisioned certificate before they can even reach application-layer logic. This is particularly important on the Consumption tier, where API Management runs multi-tenant serverless infrastructure and network-level isolation controls (like VNET integration) are more limited than on the Developer/Premium tiers.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` (`scan_resource_conf`):
- It only evaluates when `sku_name` is set and equals `["Consumption"]` — for any other tier, the result is **UNKNOWN** (not evaluated by this check).
- If `sku_name == ["Consumption"]`:
  - **PASS** if `client_certificate_enabled == [True]`.
  - **FAIL** otherwise (attribute missing or `false`).

## Non-compliant example
```hcl
resource "azurerm_api_management" "example" {
  name                = "example-apim"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  publisher_name      = "Example Org"
  publisher_email     = "admin@example.com"
  sku_name            = "Consumption"

  # client_certificate_enabled omitted -> mTLS not enforced on Consumption tier
}
```

## Remediated example
```hcl
resource "azurerm_api_management" "example" {
  name                = "example-apim"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  publisher_name      = "Example Org"
  publisher_email     = "admin@example.com"
  sku_name            = "Consumption"

  client_certificate_enabled = true   # enforces client certificate authentication
}
```

## Remediation steps
1. For any `azurerm_api_management` resource using `sku_name = "Consumption"`, add `client_certificate_enabled = true`.
2. Provision and distribute client certificates to legitimate API consumers, and configure certificate validation policies in APIM as needed.
3. If you are not on the Consumption tier, this specific check does not apply — but consider equivalent controls (mutual TLS via inbound policies, VNET integration) for other tiers.
4. Test client integrations after enabling, since callers without a valid certificate will be rejected once enforced.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIManagementCertsEnforced.py)
- [Azure API Management client certificate documentation](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates-for-clients)
