# CKV_AZURE_15: Ensure web app is using the latest version of TLS encryption

## Severity
**MEDIUM** (score: 5.5/10)

Permitting outdated TLS versions on a web app weakens in-transit encryption and exposes it to known protocol downgrade/cipher weaknesses, though it still requires network interception to exploit.

## Summary
This check ensures that an Azure App Service / Web App enforces a minimum TLS version of 1.2 (or 1.3) for inbound HTTPS connections, rather than allowing older, insecure TLS versions.

## Applicability
- **Frameworks:** Terraform, Bicep, ARM
- **Resource types:**
  - Terraform: `azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app`
  - ARM/Bicep: `Microsoft.Web/sites`

## Why it matters
TLS versions below 1.2 (TLS 1.0/1.1, and SSL) have known cryptographic weaknesses — vulnerable cipher suites, susceptibility to protocol downgrade and padding-oracle attacks (e.g. POODLE, BEAST) — and are disallowed by modern compliance frameworks (PCI-DSS 4.0, NIST 800-52). A web app that accepts connections at a lower minimum TLS version allows a man-in-the-middle attacker on the network path, or a client forced into a downgrade, to negotiate a weaker cipher suite, increasing the risk of session hijacking or data exposure for anything transmitted to/from the app (including auth cookies, tokens, and form submissions).

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Terraform:** inspects `site_config[0].min_tls_version` (for `azurerm_app_service`) or `site_config[0].minimum_tls_version` (for `azurerm_linux_web_app` / `azurerm_windows_web_app`). If the `site_config` block is entirely missing, the check **PASSES** (`missing_block_result=CheckResult.PASSED`) — the Azure platform default is already TLS 1.2 for newer API versions.
- **ARM/Bicep:** inspects `properties.siteConfig.minTlsVersion`.
- **PASS** if the value is `"1.2"`, `1.2`, `"1.3"`, or `1.3`.
- **FAIL** if an explicit lower value (e.g. `"1.0"` or `"1.1"`) is set.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    minimum_tls_version = "1.0"   # allows deprecated, insecure TLS 1.0
  }
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    minimum_tls_version = "1.2"   # enforces modern TLS
  }
}
```

## Remediation steps
1. Set `minimum_tls_version` (or `min_tls_version` for `azurerm_app_service`) to `"1.2"` (or `"1.3"` where supported) inside the `site_config` block.
2. For ARM/Bicep templates, set `properties.siteConfig.minTlsVersion` to `"1.2"`.
3. This is an in-place configuration change — no resource replacement is required.
4. Verify legacy client integrations (older devices, third-party webhooks) support TLS 1.2 before enforcing, since older clients that only speak TLS 1.0/1.1 will be rejected.
5. Apply the same setting consistently to any deployment slots (see CKV_AZURE_154 for slot-level TLS enforcement).

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceMinTLSVersion.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceMinTLSVersion.py)
- [Azure App Service TLS/SSL documentation](https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings)
