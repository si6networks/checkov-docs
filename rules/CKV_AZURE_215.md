# CKV_AZURE_215: Ensure API management backend uses https
## Severity
**HIGH** (score: 7.5/10)

An API Management backend reachable over plain HTTP transmits request/response data (potentially including credentials or tokens) in cleartext, exposing it to interception or tampering on the network path.

## Summary
Ensures that an Azure API Management backend is configured to communicate with its backend service over HTTPS rather than plaintext HTTP.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_api_management_backend` — inspects the `url` attribute

## Why it matters
An API Management "backend" entity defines the actual origin service that API Management proxies requests to. If that backend URL uses `http://` instead of `https://`, all traffic between the API Management gateway and the backend service travels unencrypted. This exposes request/response bodies (which may contain API keys, session tokens, PII, or other sensitive payloads), headers (including authorization headers forwarded to the backend), and query parameters to interception or tampering by anyone with visibility into the network path — an on-path attacker, a compromised router, or a misconfigured VNet peering. Since API Management often sits in front of internal microservices, assuming the backend link is "internal and therefore safe" is a common but risky assumption; enforcing HTTPS end-to-end (client → APIM → backend) removes this trust gap and protects against network-level eavesdropping and man-in-the-middle attacks even within a supposedly trusted network.

## How Checkov evaluates this
The check reads the `url` attribute of the `azurerm_api_management_backend` resource.
- If `url` is present and the substring `"https"` appears anywhere in the value, the check **PASSES**.
- If `url` is present but does not contain `"https"`, the check **FAILS**.
- If `url` cannot be resolved to a list value, the result is `UNKNOWN`.

## Non-compliant example
```hcl
resource "azurerm_api_management_backend" "example" {
  name                = "example-backend"
  resource_group_name = azurerm_resource_group.example.name
  api_management_name = azurerm_api_management.example.name
  protocol            = "http"
  url                 = "http://backend.internal.contoso.com/api"
}
```

## Remediated example
```hcl
resource "azurerm_api_management_backend" "example" {
  name                = "example-backend"
  resource_group_name = azurerm_resource_group.example.name
  api_management_name = azurerm_api_management.example.name
  protocol            = "http"
  url                 = "https://backend.internal.contoso.com/api"   # HTTPS backend
}
```

## Remediation steps
1. Change the `url` attribute to use the `https://` scheme.
2. Ensure the backend service has a valid TLS certificate installed and terminates TLS correctly (self-signed certs may require additional `tls` validation settings on the backend resource, e.g. `tls { validate_certificate_chain = false }` only if truly necessary and understood).
3. If the backend previously listened only on port 80/HTTP, update its own configuration to also (or only) serve HTTPS, then update the firewall/NSG rules accordingly.
4. Re-test API calls end-to-end through API Management after the change to confirm connectivity is not broken by certificate trust issues.
5. Consider also enforcing HTTPS-only at the API Management gateway/API level (inbound) in addition to the backend (outbound) leg for full end-to-end encryption.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIManagementBackendHTTPS.py
- Azure docs: https://learn.microsoft.com/en-us/azure/api-management/backends
