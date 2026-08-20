# CKV_AZURE_14: Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service
## Severity
**HIGH** (score: 7.0/10)

Not forcing HTTPS-only on an App Service allows plaintext HTTP traffic to be served or accepted, exposing session tokens, cookies, and application data to interception (missing encryption in transit).

## Summary
This check ensures an Azure App Service (Web App) has the "HTTPS Only" setting enabled so that all inbound HTTP requests are redirected to HTTPS rather than served in plaintext.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **ARM**: `Microsoft.Web/sites` resources, property `properties/httpsOnly`.
- **Terraform**: `azurerm_app_service`, `azurerm_linux_web_app`, and `azurerm_windows_web_app` resources, attribute `https_only`.
- **Bicep**: compiles to the same ARM resource type.

## Why it matters
When HTTPS-only enforcement is disabled, the App Service accepts and serves plain HTTP traffic on port 80 in addition to HTTPS. Any request that arrives over unencrypted HTTP — whether from a user typing `http://` manually, a stale bookmark/link, or a client that never gets upgraded — is transmitted in cleartext. This exposes cookies (including session/auth cookies), authentication headers, form submissions, and any other request/response content to interception or tampering by an on-path attacker (e.g. on public Wi-Fi, a compromised router, or a malicious proxy). It also enables SSL-stripping style downgrade attacks where an attacker intercepts the initial HTTP request and never lets the client reach the HTTPS version at all. Enforcing HTTPS-only at the platform level guarantees every request is redirected (HTTP 301/302) to the HTTPS endpoint, closing this gap regardless of application-level behavior.

## How Checkov evaluates this
- **ARM**: Checks `conf['properties']['httpsOnly']`; if present and its string form (case-insensitive) equals `"true"`, the check PASSES; otherwise (missing `properties`, missing key, or any other value) it FAILS.
- **Terraform**: A `BaseResourceValueCheck` inspecting `https_only/[0]` (the `https_only` attribute) and expecting it to be truthy by default (no custom `get_expected_value` override, so the base class's default expected value of `True` applies). If omitted, provider default behavior/values determine pass/fail; explicitly setting `https_only = true` PASSES.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id
  https_only          = false  # FAILS -- plaintext HTTP traffic accepted

  site_config {}
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id
  https_only          = true  # all HTTP requests redirected to HTTPS

  site_config {}
}
```

## Remediation steps
1. Set `https_only = true` (Terraform) or `properties.httpsOnly: true` (ARM/Bicep) on the App Service / Web App resource.
2. Confirm a valid TLS certificate (managed certificate, App Service Certificate, or custom binding) is configured on the app's custom domain(s) before enforcing HTTPS-only, or clients on those domains will fail to connect.
3. Also set an appropriate `minimum_tls_version` (e.g. `1.2`) in `site_config` for defense in depth alongside HTTPS enforcement.
4. Update any hardcoded `http://` links in application code, health checks, or monitoring probes to `https://` to avoid unnecessary redirect hops.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceHTTPSOnly.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHTTPSOnly.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https
