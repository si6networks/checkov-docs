# CKV_AZURE_173: Ensure API management uses at least TLS 1.2

## Severity
**HIGH** (score: 7.5/10)

Allowing SSL3/TLS1.0/1.1 negotiation on an API gateway that handles auth tokens and sensitive payloads creates a downgrade attack surface exploitable via known protocol-level weaknesses (e.g., POODLE, BEAST) to compromise traffic confidentiality or integrity.

## Summary
This check ensures an Azure API Management instance does not have any legacy/weak transport protocols (SSL 3.0, TLS 1.0, TLS 1.1) explicitly enabled on either its frontend or backend connections.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_api_management` (`security` block flags).
- **ARM/Bicep**: `Microsoft.ApiManagement/service` (`properties.customProperties` flags).

## Why it matters
SSL 3.0 and TLS 1.0/1.1 are deprecated protocol versions with known cryptographic weaknesses (e.g., POODLE for SSLv3, BEAST for TLS 1.0) and are disallowed by modern compliance frameworks (PCI-DSS, etc.). API Management sits at the edge of an API surface, often handling authentication tokens and sensitive payloads; allowing legacy protocol negotiation — on the frontend (client-to-APIM) or the backend (APIM-to-origin) — creates a downgrade attack surface where a man-in-the-middle could coerce a weaker handshake and exploit protocol-level vulnerabilities to compromise confidentiality or integrity of the traffic. Restricting to TLS 1.2+ removes this negotiable weak path entirely.

## How Checkov evaluates this
- **Terraform** (`APIManagementMinTLS12`): inspects the `security` block on `azurerm_api_management` for any of `enable_backend_ssl30`, `enable_backend_tls10`, `enable_frontend_ssl30`, `enable_frontend_tls10`, `enable_frontend_tls11`. If **any** of these flags is set to `true`, the check **FAILS** immediately on that flag. If none are true (or the block/flags are absent), it **PASSES**.
- **ARM**: inspects `properties.customProperties` for keys such as `...Security.Backend.Protocols.Ssl30`, `...Backend.Protocols.Tls10`, `...Security.Protocols.Ssl30`, `...Security.Protocols.Tls10`, `...Security.Protocols.Tls11`. If any of these custom properties are set to a truthy value, the check **FAILS**; otherwise it **PASSES**.

## Non-compliant example
```hcl
resource "azurerm_api_management" "apim" {
  name                = "my-apim"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  publisher_name      = "My Company"
  publisher_email     = "admin@example.com"
  sku_name            = "Developer_1"

  security {
    enable_backend_tls10  = true
    enable_frontend_tls10 = true
  }
}
```

## Remediated example
```hcl
resource "azurerm_api_management" "apim" {
  name                = "my-apim"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  publisher_name      = "My Company"
  publisher_email     = "admin@example.com"
  sku_name            = "Developer_1"

  security {
    enable_backend_ssl30   = false
    enable_backend_tls10   = false
    enable_frontend_ssl30  = false
    enable_frontend_tls10  = false
    enable_frontend_tls11  = false
  }
}
```

## Remediation steps
1. Remove or set to `false` every `enable_*_ssl30` / `enable_*_tls10` / `enable_frontend_tls11` flag in the `security` block (or simply omit the block, since these all default to disabled).
2. For ARM/Bicep templates, ensure `customProperties` does not set any of the legacy protocol keys to `"True"`.
3. Before enforcing, confirm no legacy client or backend origin genuinely requires TLS 1.0/1.1 — coordinate a migration window with owners of any such systems, since disabling these will break connections that can't negotiate TLS 1.2+.
4. Consider also verifying/enforcing strong cipher suites via APIM's cipher configuration, as protocol version alone doesn't guarantee strong ciphers are selected.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIManagementMinTLS12.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/APIManagementMinTLS12.py
- Microsoft Docs: https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-manage-protocols-ciphers
