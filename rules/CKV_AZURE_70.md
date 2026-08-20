# CKV_AZURE_70: Ensure that Function apps is only accessible over HTTPS

## Severity
**HIGH** (score: 7.5/10)

Function Apps without enforced HTTPS transmit request/response data, function keys, and auth tokens in cleartext, allowing network-level interception or injection against internet-facing endpoints.

## Summary
This check ensures Azure Function Apps (and slots) reject plain HTTP connections and require HTTPS, and, when auth v2 settings are used, that `requireHttps` is not disabled.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_function_app`, `azurerm_linux_function_app`, `azurerm_windows_function_app`, `azurerm_function_app_slot`, `azurerm_linux_function_app_slot`, `azurerm_windows_function_app_slot`
- **ARM/Bicep**: `Microsoft.Web/sites`, `Microsoft.Web/sites/config`, `Microsoft.Web/sites/slots`

## Why it matters
Function Apps often expose HTTP-triggered endpoints (webhooks, APIs) directly to the internet. If HTTPS-only enforcement is off, an attacker on the network path (public Wi-Fi, compromised router, ISP-level MITM) can intercept traffic to or from the function, capturing bearer tokens, function keys, or request/response payloads sent in cleartext, or inject malicious responses. Azure does not disable plain HTTP by default, so this must be explicitly configured. The check also covers Azure AD auth v2 (`requireHttps`), which — if turned off — allows the platform's own authentication flow (which carries tokens) to run unencrypted.

## How Checkov evaluates this
- **Terraform**: Fails if `https_only` is absent (default is `false` in the provider) or set to `false`. If `auth_settings_v2` is present and defines `require_https`, fails when that value is `false`; if `require_https` is absent inside `auth_settings_v2`, it passes (the platform default is `true`).
- **ARM**: For `Microsoft.Web/sites`/`Microsoft.Web/sites/slots`, fails if `properties.httpsOnly` is missing or `false`. For config with `properties.httpSettings.requireHttps`, fails only if explicitly set to `false`; missing key passes (default `true`).

## Non-compliant example
```hcl
resource "azurerm_linux_function_app" "example" {
  name                       = "example-function-app"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  service_plan_id            = azurerm_service_plan.example.id

  # https_only omitted -> defaults to false, FAILS the check

  site_config {}
}
```

## Remediated example
```hcl
resource "azurerm_linux_function_app" "example" {
  name                       = "example-function-app"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  service_plan_id            = azurerm_service_plan.example.id

  https_only = true   # enforce HTTPS-only access

  site_config {}
}
```

## Remediation steps
1. Add `https_only = true` to every `azurerm_*function_app*` resource (or `properties.httpsOnly: true` in ARM/Bicep templates).
2. If using `auth_settings_v2`, either omit `require_https` (defaults to `true`) or set it explicitly to `true`.
3. Redeploy — enabling `https_only` on an existing app does not require replacement, but any client still calling the app over plain `http://` will start receiving redirects/failures, so coordinate the change with API consumers.
4. Consider also enforcing a minimum TLS version (`minTlsVersion`) alongside this setting for defense in depth.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppsAccessibleOverHttps.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/FunctionAppsAccessibleOverHttps.py
- Azure docs: https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings
