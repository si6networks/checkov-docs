# CKV_AZURE_57: Ensure that CORS disallows every resource to access app services
## Severity
**MEDIUM** (score: 6.0/10)

A wildcard CORS policy on App Services removes the browser's cross-origin protection, enabling malicious sites to read responses via a victim's authenticated session, though exploitation depends on the app actually relying on browser-attached credentials.

## Summary
This check fails when an Azure App Service's CORS configuration allows all origins (`*`), which permits any website on the internet to make cross-origin browser requests to the app service.

## Applicability
Applies to Terraform (`azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app`), ARM templates, and Bicep, for the resource type `Microsoft.Web/sites`.

## Why it matters
CORS is a browser-enforced relaxation of the same-origin policy; setting `allowedOrigins` to `*` tells browsers that responses from this app service may be read by JavaScript running on any other origin. If the app service returns any sensitive data or performs state-changing actions reachable via authenticated cross-origin requests (e.g. cookies, or credentials automatically attached by the browser), a malicious website can silently issue requests on behalf of a visiting user and read the response — a direct enabler of data exfiltration and CSRF-adjacent attacks. Even for APIs that seem "public," an open wildcard removes the ability to restrict which frontends are allowed to embed/call the service, making it easy for third parties to scrape, proxy, or abuse the API using a victim's browser session. Configuring an explicit allow-list of trusted origins keeps the browser's cross-origin protections meaningful.

## How Checkov evaluates this
This is a "negative value check" with a `missing_block_result` of PASSED: if there is no CORS block at all, the check PASSES (default App Service CORS is closed). If a CORS configuration exists, Checkov looks at `allowedOrigins` (`properties/siteConfig/cors/allowedOrigins` in ARM/Bicep, `site_config[0].cors[0].allowed_origins` in Terraform) and FAILS only if that list contains the forbidden value `"*"`. Any explicit list of specific origins PASSES.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    cors {
      allowed_origins = ["*"]
    }
  }
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    cors {
      allowed_origins = ["https://app.example.com"]  # explicit trusted origin only
    }
  }
}
```

## Remediation steps
1. Replace the `["*"]` wildcard in the `cors.allowed_origins` list with the exact scheme+host(+port) of every legitimate frontend that needs to call this app service.
2. If truly no cross-origin access is needed, remove the `cors` block entirely (the check treats a missing block as compliant).
3. Avoid dynamically reflecting the request's `Origin` header as an "allow all" workaround in application code — that defeats CORS protection just as thoroughly as `*`.
4. If credentials (cookies, Authorization headers) are used cross-origin, ensure `support_credentials`/`Access-Control-Allow-Credentials` is only enabled alongside a strict origin allow-list, never with a wildcard (browsers disallow combining `*` with credentials anyway).
5. Re-test any legitimate third-party integrations after narrowing the origin list to confirm they're not broken.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceDisallowCORS.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDisallowCORS.py)
- [MDN: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
