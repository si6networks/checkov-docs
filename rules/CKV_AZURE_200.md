# CKV_AZURE_200: Ensure the Azure CDN endpoint is using the latest version of TLS encryption

## Severity
**HIGH** (score: 7.0/10)

Allowing TLS 1.0 (or no explicit version) on a CDN custom domain permits negotiation of a cryptographically weak protocol, letting a network-positioned attacker downgrade or exploit the connection to intercept or tamper with content served to end users.

## Summary
This check ensures that HTTPS custom domain configurations on an Azure CDN endpoint use TLS 1.2 (not TLS 1.0 or no explicit version), whether HTTPS is provided via CDN-managed or user-managed certificates.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `azurerm_cdn_endpoint_custom_domain`

## Why it matters
TLS 1.0 (and the absence of an explicit minimum, which can fall back to older negotiated protocols) has known cryptographic weaknesses, including vulnerability to the BEAST attack and reliance on weaker cipher suites and hash algorithms that fail to meet modern compliance baselines (PCI-DSS explicitly disallows TLS 1.0/1.1). An attacker capable of intercepting the connection (a man-in-the-middle on a shared network, a malicious CDN edge peer, or an attacker exploiting a vulnerable client/server negotiation) can potentially downgrade or exploit protocol weaknesses to decrypt or tamper with traffic between end users and content served through the CDN's custom domain. Enforcing TLS 1.2 removes support for those legacy, weaker protocol versions at the edge closest to end users.

## How Checkov evaluates this
Custom `scan_resource_conf` logic in a `BaseResourceCheck`:
- Defines `INSECURE_TLS_VERSIONS = ("None", "TLS10")`.
- If a `cdn_managed_https` block exists and its `tls_version` is one of the insecure values, the check FAILS.
- If a `user_managed_https` block exists and its `tls_version` is one of the insecure values, the check FAILS.
- If neither block sets an insecure TLS version (including cases where `tls_version` defaults to `TLS12` or is unset), the check PASSES.

## Non-compliant example
```hcl
resource "azurerm_cdn_endpoint_custom_domain" "example" {
  name            = "example-domain"
  cdn_endpoint_id = azurerm_cdn_endpoint.example.id
  host_name       = "www.contoso.com"

  cdn_managed_https {
    certificate_type = "Dedicated"
    protocol_type     = "ServerNameIndication"
    tls_version       = "TLS10"   # insecure
  }
}
```

## Remediated example
```hcl
resource "azurerm_cdn_endpoint_custom_domain" "example" {
  name            = "example-domain"
  cdn_endpoint_id = azurerm_cdn_endpoint.example.id
  host_name       = "www.contoso.com"

  cdn_managed_https {
    certificate_type = "Dedicated"
    protocol_type     = "ServerNameIndication"
    tls_version       = "TLS12"   # enforce modern TLS
  }
}
```

## Remediation steps
1. Find every `azurerm_cdn_endpoint_custom_domain` resource with a `cdn_managed_https` or `user_managed_https` block.
2. Set `tls_version = "TLS12"` explicitly (do not leave it as `"TLS10"` or `"None"`).
3. If using `user_managed_https` with a Key Vault certificate, confirm the certificate and any client integrations support TLS 1.2 before enforcing, since older clients that only support TLS 1.0/1.1 will be unable to connect.
4. Apply and validate with an external TLS scan (e.g. `openssl s_client -tls1_2`) against the custom domain to confirm the negotiated protocol.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CDNTLSProtocol12.py)
- [Azure CDN custom domain HTTPS documentation](https://learn.microsoft.com/en-us/azure/cdn/cdn-custom-ssl)
