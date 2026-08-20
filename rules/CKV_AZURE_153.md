# CKV_AZURE_153: Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service Slot

## Severity
**HIGH** (score: 7.0/10)

Not forcing HTTPS on an App Service slot allows plaintext HTTP traffic, exposing requests, responses, cookies, and tokens to interception and tampering over the network.

## Summary
This check ensures that Azure App Service deployment slots enforce HTTPS-only traffic (`httpsOnly` / `https_only`), so plain HTTP requests are redirected to HTTPS rather than served in the clear.

## Applicability
- **Frameworks:** Terraform, Bicep, ARM
- **Resource types:**
  - Terraform: `azurerm_app_service_slot`, `azurerm_linux_web_app_slot`, `azurerm_windows_web_app_slot`
  - ARM/Bicep: `Microsoft.Web/sites`, `Microsoft.Web/sites/slots`

## Why it matters
Deployment slots (staging, QA, canary, etc.) are often overlooked in security reviews because they're treated as "not production," yet they run the same application code and frequently process the same kind of data — including test data that may mirror production, or even production traffic during blue/green swaps. If HTTPS-only is not enforced on a slot, an attacker on the network path (public Wi-Fi, compromised router, ISP-level monitoring) can intercept plaintext HTTP traffic to that slot, capturing cookies, auth tokens, or form submissions, or inject content via a man-in-the-middle attack. Enforcing HTTPS-only redirection closes this gap consistently across all slots, not just the production site.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Terraform:** inspects `https_only` on the slot resource.
- **ARM/Bicep:** inspects `properties.httpsOnly`.
- **PASS** if the value is `true`.
- **FAIL** if `false` or omitted (default missing-block behavior for `BaseResourceValueCheck` is FAILED).

## Non-compliant example
```hcl
resource "azurerm_linux_web_app_slot" "staging" {
  name           = "staging"
  app_service_id = azurerm_linux_web_app.example.id

  # https_only omitted -> plain HTTP traffic accepted on this slot

  site_config {}
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app_slot" "staging" {
  name           = "staging"
  app_service_id = azurerm_linux_web_app.example.id

  https_only = true   # forces redirect of all HTTP traffic to HTTPS

  site_config {}
}
```

## Remediation steps
1. Set `https_only = true` (Terraform) or `properties.httpsOnly: true` (ARM/Bicep) on every deployment slot resource, matching the setting already applied (or that should be applied) to the parent app.
2. This is an in-place configuration change — no resource replacement is required.
3. Confirm custom domains bound to the slot have valid TLS certificates configured, since enabling HTTPS-only without a working cert will break access.
4. Apply the same minimum TLS version hardening (see CKV_AZURE_154) alongside this setting for complete transport security on slots.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceSlotHTTPSOnly.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceSlotHTTPSOnly.py)
- [Azure App Service HTTPS enforcement documentation](https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https)
