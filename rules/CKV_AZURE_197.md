# CKV_AZURE_197: Ensure the Azure CDN disables the HTTP endpoint

## Severity
**MEDIUM** (score: 5.0/10)

Leaving the HTTP endpoint enabled only permits optional plaintext delivery of CDN content rather than forcing it, and CDN-fronted content is typically public/static, so on-path interception is a real but moderate confidentiality/integrity risk.

## Summary
This check ensures that an Azure CDN endpoint does not allow plaintext HTTP delivery of content, requiring `is_http_allowed` to be set to `false`.

## Applicability
- **Framework:** Terraform
- **Resource type:** `azurerm_cdn_endpoint`

## Why it matters
Azure CDN endpoints can be configured to accept requests over both HTTP and HTTPS. When the HTTP endpoint is left enabled, clients (or misconfigured links/redirects) can retrieve content over an unencrypted channel. Traffic sent over plain HTTP is susceptible to on-path interception, tampering, and downgrade attacks — an attacker positioned on the network path (e.g. a rogue Wi-Fi access point, compromised router, or ISP-level intercepting proxy) can read or modify content in transit, inject malicious payloads (such as malicious JavaScript into HTML/JS assets served via the CDN), or harvest any sensitive query-string data or headers sent in the clear. Disabling the HTTP endpoint forces all delivery through HTTPS, eliminating this class of attack for CDN-served content.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `is_http_allowed` attribute on `azurerm_cdn_endpoint`:
- **Inspected key:** `is_http_allowed`
- **Expected value:** `False`
- The check FAILS if `is_http_allowed` is `true` (or unset with a default that resolves to `true`, since Terraform's default for this argument is `true`).
- The check PASSES only when `is_http_allowed` is explicitly `false`.

## Non-compliant example
```hcl
resource "azurerm_cdn_endpoint" "example" {
  name                = "example-endpoint"
  profile_name        = azurerm_cdn_profile.example.name
  location            = azurerm_cdn_profile.example.location
  resource_group_name = azurerm_resource_group.example.name

  is_http_allowed  = true
  is_https_allowed = true

  origin {
    name      = "example-origin"
    host_name = "www.contoso.com"
  }
}
```

## Remediated example
```hcl
resource "azurerm_cdn_endpoint" "example" {
  name                = "example-endpoint"
  profile_name        = azurerm_cdn_profile.example.name
  location            = azurerm_cdn_profile.example.location
  resource_group_name = azurerm_resource_group.example.name

  is_http_allowed  = false  # HTTP endpoint disabled
  is_https_allowed = true

  origin {
    name      = "example-origin"
    host_name = "www.contoso.com"
  }
}
```

## Remediation steps
1. Locate every `azurerm_cdn_endpoint` resource in your Terraform configuration.
2. Set `is_http_allowed = false`.
3. Ensure `is_https_allowed = true` is also set (see CKV_AZURE_198) so clients still have a working, encrypted path.
4. Update any hardcoded `http://` links, integrations, or health checks that depend on the CDN's HTTP endpoint to use `https://` instead before applying, since this change removes the plaintext path entirely.
5. Apply via `terraform apply`; this is a non-disruptive in-place update (no resource replacement) but will start rejecting any HTTP requests immediately, so validate downstream consumers first.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CDNDisableHttpEndpoints.py)
- [Azure CDN endpoint HTTPS documentation](https://learn.microsoft.com/en-us/azure/cdn/cdn-custom-ssl)
