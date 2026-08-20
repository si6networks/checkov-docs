# CKV_AZURE_221: Ensure that Azure Function App public network access is disabled
## Severity
**HIGH** (score: 7.5/10)

A Function App with public network access enabled exposes its HTTP-triggered endpoints and management surface directly to the internet, broadening the attack surface for compute resources that often hold sensitive logic or credentials.

## Summary
Ensures that Azure Function Apps are not reachable directly from the public internet, requiring access via private networking (VNet integration / private endpoints) instead.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_linux_function_app`, `azurerm_linux_function_app_slot`, `azurerm_windows_function_app`, `azurerm_windows_function_app_slot` — inspects `public_network_access_enabled`

## Why it matters
Function Apps often host event-driven or backend business logic — including code that processes webhooks, integrates with internal systems, or has elevated permissions via managed identities. When `public_network_access_enabled` is left at its default (`true`), the function's HTTP-triggered endpoints are reachable from any IP address on the internet, subject only to whatever application-level authentication is configured. This significantly widens the attack surface: it exposes the function to internet-wide scanning, brute-force attempts against any auth keys, exploitation of unpatched runtime/framework vulnerabilities, and denial-of-service traffic — all before any application logic even executes. Disabling public network access and requiring traffic to arrive via a private endpoint or VNet integration confines exposure to your organization's private network boundary, so that even a misconfigured or overly-permissive function-level authorization setting doesn't translate into direct internet exposure.

## How Checkov evaluates this
The check inspects `public_network_access_enabled`. The expected value is `False`. The check **PASSES** only when this attribute is explicitly set to `false`; it **FAILS** if set to `true` or left unset (Azure's default for this attribute is `true`, i.e., public access enabled).

## Non-compliant example
```hcl
resource "azurerm_linux_function_app" "example" {
  name                       = "example-func"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  service_plan_id            = azurerm_service_plan.example.id

  # public_network_access_enabled left unset -> defaults to true (public)
  site_config {}
}
```

## Remediated example
```hcl
resource "azurerm_linux_function_app" "example" {
  name                       = "example-func"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  service_plan_id            = azurerm_service_plan.example.id

  public_network_access_enabled = false   # block direct internet access

  site_config {}
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` on the Function App (and any slots).
2. Before disabling public access, provision a private endpoint (`azurerm_private_endpoint` targeting the `sites` sub-resource) or VNet-integrate the Function App, so it remains reachable from your private network / hub-and-spoke topology.
3. Update any callers (webhooks from third-party SaaS, other Azure services, CI/CD pipelines) that currently reach the function over its public URL — they will need to be routed through the private network, via VPN/ExpressRoute, or via an API Management/Application Gateway front end with private connectivity to the function.
4. If selective public access is needed (rather than fully private), consider `ip_restriction` rules on `site_config` as an interim compensating control, but note this check specifically requires `public_network_access_enabled = false` to pass.
5. Test end-to-end connectivity after the change, since public trigger URLs (e.g., HTTP trigger endpoints) will stop resolving from outside the private network.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppPublicAccessDisabled.py
- Azure docs: https://learn.microsoft.com/en-us/azure/azure-functions/functions-networking-options
