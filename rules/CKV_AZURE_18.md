# CKV_AZURE_18: Ensure that 'HTTP Version' is the latest if used to run the web app

## Severity
**LOW** (score: 2.5/10)

Running HTTP/1.1 instead of HTTP/2 is primarily a performance/modernization concern; the security implications (marginally larger metadata exposure, connection-handling differences) are secondary and do not represent a direct exploitable weakness.

## Summary
This check ensures that an Azure App Service / Web App has HTTP/2 enabled in its site configuration, rather than being left on the older HTTP/1.1-only default.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app` (`site_config[0].http2_enabled`).
- **ARM/Bicep**: `Microsoft.Web/sites` (`properties.siteConfig.http20Enabled` — represented as a string in older API versions, boolean in newer ones).

## Why it matters
This is primarily a performance and modernization control rather than a direct confidentiality/integrity control, but it has security-adjacent implications: HTTP/2 mandates TLS in virtually all real-world browser implementations (even though the protocol spec technically allows cleartext), multiplexes requests over a single connection reducing the number of exposed TCP/TLS handshakes, and header compression (HPACK) reduces certain metadata leakage patterns present in verbose HTTP/1.1 header exchanges. More concretely, staying on HTTP/1.1 means missing head-of-line-blocking fixes and connection-reuse improvements that reduce the number of live connections an app must defend/monitor, and it signals a web app configuration that hasn't been reviewed/updated — often correlated with other stale defaults (TLS version, cipher policy) not having been revisited either.

## How Checkov evaluates this
- **ARM** (`AppServiceHttps20Enabled`): looks up `properties.siteConfig.http20Enabled` via a dict-path search. Because Microsoft changed the property's JSON type across API versions, the check branches on the resource's `apiVersion`:
  - If `apiVersion == "2018-11-01"`, the value is expected to be the **string** `"true"` (case-insensitive).
  - Otherwise, the value is expected to be the **boolean** `true`.
  - Any other value, or the property being absent, **FAILS**.
- **Terraform** (`AppServiceHttps20Enabled`, a `BaseResourceValueCheck`): inspects `site_config/[0]/http2_enabled` and expects it to be `true`; missing or `false` **FAILS**.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "app" {
  name                = "my-webapp"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  service_plan_id     = azurerm_service_plan.plan.id

  site_config {
    # http2_enabled not set -> defaults to false
  }
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app" "app" {
  name                = "my-webapp"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  service_plan_id     = azurerm_service_plan.plan.id

  site_config {
    http2_enabled = true
  }
}
```

## Remediation steps
1. Add `http2_enabled = true` inside the `site_config` block of the web app resource.
2. For ARM/Bicep templates, set `properties.siteConfig.http20Enabled` to `true` (boolean) on API versions `2020-10-01` and later, or the string `"true"` on `2018-11-01`.
3. Verify no legacy client or load-balancer/WAF in front of the app lacks HTTP/2 support before enabling — most modern browsers and Azure Front Door/Application Gateway support it, but custom/legacy intermediaries occasionally don't.
4. This is a low-risk, non-disruptive configuration change that typically does not require downtime, but validate in a staging slot first for apps with unusual client requirements.
5. Consider pairing this with a review of minimum TLS version and cipher suite settings on the same App Service, since both are commonly-stale defaults on older web apps.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHttps20Enabled.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceHttps20Enabled.py
