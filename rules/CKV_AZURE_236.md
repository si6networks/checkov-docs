# CKV_AZURE_236: Ensure that Cognitive Services accounts disable local authentication

## Severity
**LOW** (score: 2.0/10)

Leaving local (API-key) authentication enabled on Cognitive Services accounts allows access via a static shared key instead of Azure AD identity, materially widening the credential-theft attack surface for a sensitive AI/data service.

## Summary
This check ensures that Azure Cognitive Services accounts require Azure AD (Entra ID) authentication instead of allowing local key-based authentication (API keys).

## Applicability
- **Terraform**: `azurerm_cognitive_account` resources — inspects the `local_auth_enabled` attribute (expects `false`).
- **ARM/Bicep**: `Microsoft.CognitiveServices/accounts` — inspects `properties.disableLocalAuth` (expects `true`).

## Why it matters
Cognitive Services (Azure OpenAI, Computer Vision, Speech, Language, etc.) support two authentication modes: a static API key ("local auth") and Azure AD token-based authentication. API keys are long-lived, bearer-style secrets — anyone who obtains one (via source code leakage, a compromised CI pipeline, a misconfigured config file, or a shared secrets store) gets full access to the account with no per-identity accountability and no easy way to revoke access for a single consumer without rotating the key for everyone. Azure AD authentication, by contrast, issues short-lived tokens tied to a specific managed identity or service principal, supports Conditional Access policies (e.g., requiring specific networks or MFA), and produces per-identity audit trails in Azure AD sign-in logs. Disabling local auth removes the API-key attack surface entirely, forcing all callers through Azure AD's stronger identity and access controls.

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck`s:
- **Terraform**: inspects `local_auth_enabled` on `azurerm_cognitive_account`. PASSES only if the value is exactly `false`; FAILS if `true` or unset (Terraform provider defaults this to `true`, i.e., local auth enabled by default).
- **ARM**: inspects `properties.disableLocalAuth`. PASSES only if the value is exactly `true`; FAILS otherwise.

## Non-compliant example
```hcl
resource "azurerm_cognitive_account" "example" {
  name                = "example-cognitive"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  kind                = "OpenAI"
  sku_name            = "S0"
  # local_auth_enabled not set -> defaults to true, FAILS
}
```

## Remediated example
```hcl
resource "azurerm_cognitive_account" "example" {
  name                = "example-cognitive"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  kind                = "OpenAI"
  sku_name            = "S0"
  local_auth_enabled  = false   # <-- forces Azure AD auth only, PASSES
}
```

## Remediation steps
1. Set `local_auth_enabled = false` (Terraform) or `properties.disableLocalAuth: true` (ARM/Bicep) on the Cognitive Services account.
2. Update all client applications and SDKs to authenticate using Azure AD tokens (e.g., `DefaultAzureCredential` in the Azure SDKs) via a managed identity or service principal, instead of an API key.
3. Grant the appropriate Cognitive Services RBAC role (e.g., `Cognitive Services User`, `Cognitive Services OpenAI User`) to each calling identity.
4. Rotate/revoke any existing API keys after cutover, since disabling local auth prevents new key-based calls but doesn't retroactively invalidate keys that may be cached elsewhere.
5. Test thoroughly before rollout — third-party tools or older SDK versions that only support key-based auth will break once local auth is disabled.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CognitiveServicesEnableLocalAuth.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/CognitiveServicesEnableLocalAuth.py
- Azure docs: https://learn.microsoft.com/en-us/azure/ai-services/authentication
