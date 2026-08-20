# CKV_AZURE_198: Ensure the Azure CDN enables the HTTPS endpoint

## Severity
**MEDIUM** (score: 5.5/10)

Disabling the HTTPS delivery endpoint removes the only encrypted transport option for CDN-served content, exposing all traffic on that endpoint to interception and tampering, though impact is bounded by the typically public nature of CDN content.

## Summary
This check ensures that an Azure CDN endpoint has the HTTPS delivery endpoint enabled (`is_https_allowed = true`), so content can be served over TLS.

## Applicability
- **Framework:** Terraform
- **Resource type:** `azurerm_cdn_endpoint`

## Why it matters
The HTTPS endpoint is the only way an Azure CDN endpoint can serve content over an encrypted, authenticated channel. If HTTPS delivery is disabled, all traffic served by that CDN endpoint — HTML, JavaScript, images, API responses, etc. — travels unencrypted (assuming the HTTP endpoint is enabled) or the endpoint may be unreachable for HTTPS-only clients. Without TLS termination at the CDN, users are exposed to eavesdropping, content injection, session/cookie theft, and man-in-the-middle attacks, and browsers increasingly refuse to load mixed-content or non-HTTPS resources at all, degrading availability. Since CDNs commonly front public-facing web content, disabling HTTPS undermines confidentiality and integrity guarantees for potentially large volumes of end-user traffic.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `is_https_allowed` attribute:
- **Inspected key:** `is_https_allowed`
- **Expected value:** the check's default expected value (`True`, inherited from the base class default since no `get_expected_value` override is present).
- **Special case:** `missing_block_result=CheckResult.PASSED` — if the `is_https_allowed` attribute is entirely absent from the config, Checkov treats this as a PASS (matching Azure's default behavior where `is_https_allowed` defaults to `true`).
- The check FAILS only when `is_https_allowed` is explicitly set to `false`.

## Non-compliant example
```hcl
resource "azurerm_cdn_endpoint" "example" {
  name                = "example-endpoint"
  profile_name        = azurerm_cdn_profile.example.name
  location            = azurerm_cdn_profile.example.location
  resource_group_name = azurerm_resource_group.example.name

  is_https_allowed = false
  is_http_allowed  = true

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

  is_https_allowed = true   # HTTPS endpoint enabled
  is_http_allowed  = false

  origin {
    name      = "example-origin"
    host_name = "www.contoso.com"
  }
}
```

## Remediation steps
1. Search Terraform configs for `azurerm_cdn_endpoint` resources with `is_https_allowed = false` and remove or flip that setting.
2. If omitted, no action is required — the Azure default (`true`) already satisfies this check.
3. Pair with CKV_AZURE_197 (disable the HTTP endpoint) and CKV_AZURE_200 (enforce TLS 1.2) to fully lock down transport security for the CDN endpoint.
4. If using custom domains with CDN-managed or user-managed HTTPS, verify the associated `cdn_managed_https` / `user_managed_https` block is correctly certificated before enabling in production.
5. Apply via `terraform apply` — this is a non-disruptive attribute update.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CDNEnableHttpsEndpoints.py)
- [Azure CDN custom domain HTTPS documentation](https://learn.microsoft.com/en-us/azure/cdn/cdn-custom-ssl)
