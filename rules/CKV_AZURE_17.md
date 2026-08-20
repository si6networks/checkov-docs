# CKV_AZURE_17: Ensure the web app has 'Client Certificates (Incoming client certificates)' set

## Severity
**MEDIUM** (score: 5.5/10)

Missing mutual TLS client certificate validation removes a defense-in-depth authentication layer for sensitive internal/partner APIs, but the app is not left fully unauthenticated since other controls (API keys, network policy) may still apply.

## Summary
This check ensures that an Azure App Service / Web App requires and enforces incoming client TLS certificates (mutual TLS) rather than accepting connections without client-side certificate verification.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app`.
- **ARM/Bicep**: `Microsoft.Web/sites`.

## Why it matters
By default, App Service only authenticates the server to the client (standard TLS) — it does not verify who is calling in. For app-to-app or B2B scenarios where the web app should only accept requests from specific trusted callers (e.g., internal services, partner systems, an API gateway), relying solely on network controls or application-layer API keys leaves a gap: any client that can reach the endpoint over the network can attempt requests, and secrets/API keys can leak or be replayed. Client certificate authentication (mutual TLS) requires each caller to present a certificate that the app validates before processing the request, providing strong, non-repudiable client identity at the transport layer — a meaningful defense-in-depth control for sensitive internal or partner-facing APIs.

## How Checkov evaluates this
- **Terraform** (`AppServiceClientCertificate`, a value check with `missing_block_result=FAILED`): inspects `client_cert_enabled` (for `azurerm_app_service`) or `client_certificate_enabled` (for `azurerm_linux_web_app`/`azurerm_windows_web_app`). If that attribute is `true`, the check **PASSES**; if absent or `false`, it **FAILS**.
- **ARM**: inspects `properties.clientCertEnabled` on `Microsoft.Web/sites`. If present and its string value (case-insensitive) is `"true"`, the check **PASSES**; otherwise it **FAILS** (the property defaults to `false` in ARM).

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "app" {
  name                = "my-webapp"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  service_plan_id     = azurerm_service_plan.plan.id

  site_config {}
  # client_certificate_enabled not set -> defaults to false
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app" "app" {
  name                        = "my-webapp"
  location                    = azurerm_resource_group.rg.location
  resource_group_name         = azurerm_resource_group.rg.name
  service_plan_id             = azurerm_service_plan.plan.id
  client_certificate_enabled  = true
  client_certificate_mode     = "Required"

  site_config {}
}
```

## Remediation steps
1. Set `client_certificate_enabled = true` (and, on the newer resources, `client_certificate_mode = "Required"` or `"Optional"` as appropriate) on the web app resource.
2. For `azurerm_app_service` (legacy resource), set `client_cert_enabled = true` instead.
3. Update application code / middleware to validate the client certificate's thumbprint or issuer against an allowlist — enabling the setting alone only makes the certificate available to the app via request headers, it does not by itself authorize specific certificates.
4. Coordinate certificate issuance/distribution with calling systems (internal CA, partner-provided certs) before enforcing `Required` mode, since it will reject any caller that doesn't present a certificate.
5. Consider this control complementary to network-layer restrictions (Private Endpoints, IP restrictions) rather than a replacement for them.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceClientCertificate.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceClientCertificate.py
- Microsoft Docs: https://learn.microsoft.com/en-us/azure/app-service/app-service-web-configure-tls-mutual-auth
