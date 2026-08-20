# CKV_AZURE_238: Ensure that all Azure Cognitive Services accounts are configured with a managed identity

## Severity
**LOW** (score: 2.0/10)

Not configuring a managed identity for Cognitive Services accounts pushes teams toward static credentials for service-to-service auth, moderately increasing the risk of credential leakage and misconfiguration.

## Summary
This check ensures Azure Cognitive Services accounts have a managed identity (system-assigned or user-assigned) configured, rather than relying purely on other credential types for access to other Azure resources.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_cognitive_account` resources — inspects `identity[0].type` (any non-empty value is accepted).
- **ARM/Bicep**: `Microsoft.CognitiveServices/accounts` — inspects `properties.identity.type` (any non-empty value accepted).

## Why it matters
Cognitive Services accounts frequently need to reach other Azure resources — for example, to read training data or documents from a storage account, to access a customer-managed key in Key Vault for encryption, or to write output to another service. Without a managed identity, these interactions must be authenticated with long-lived static credentials (connection strings, SAS tokens, storage keys, or service principal secrets) that need to be stored somewhere (often in application config or a secrets manager) and manually rotated. Managed identities eliminate that class of credential-management risk entirely: Azure AD issues short-lived tokens automatically, there's no secret to leak, rotate, or accidentally commit to source control, and access can be scoped tightly via RBAC role assignments tied to the specific Cognitive Services resource's identity. Using a managed identity is also a prerequisite for several other Cognitive Services security features (e.g., customer-managed key encryption, private storage account access) that themselves require an identity to authenticate.

## How Checkov evaluates this
Both are `BaseResourceValueCheck`s using `ANY_VALUE` as the expected value (i.e., pass if the key exists and is non-empty, regardless of which specific value it holds):
- **Terraform**: inspects `identity[0].type`. PASSES if any identity type (`SystemAssigned`, `UserAssigned`, or `SystemAssigned, UserAssigned`) is configured; FAILS if no `identity` block is present.
- **ARM**: inspects `properties.identity.type` similarly — any configured type passes, absence fails.

## Non-compliant example
```hcl
resource "azurerm_cognitive_account" "example" {
  name                = "example-cognitive"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  kind                = "TextAnalytics"
  sku_name            = "S0"
  # no identity block -> FAILS
}
```

## Remediated example
```hcl
resource "azurerm_cognitive_account" "example" {
  name                = "example-cognitive"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  kind                = "TextAnalytics"
  sku_name            = "S0"

  identity {
    type = "SystemAssigned"   # <-- managed identity configured, PASSES
  }
}
```

## Remediation steps
1. Add an `identity` block to the `azurerm_cognitive_account` resource with `type = "SystemAssigned"` (simplest, one identity per resource) or `type = "UserAssigned"` with an `identity_ids` list referencing a shared user-assigned identity.
2. Grant this identity the RBAC roles it needs on any target resource — for example, `Storage Blob Data Reader` on a storage account it needs to read training data from, or `Key Vault Crypto Service Encryption User` if used for customer-managed key encryption.
3. Update dependent resources (storage accounts, Key Vault access policies) to trust this identity rather than a static connection string or key.
4. If you later configure customer-managed key encryption (see CKV-style CMK checks) or private-network access to a linked storage account, verify the correct identity type (system vs. user-assigned) is used, since some Cognitive Services features require a user-assigned identity specifically.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CognitiveServicesConfigureIdentity.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/CognitiveServicesConfigureIdentity.py
- Azure docs: https://learn.microsoft.com/en-us/azure/ai-services/authentication#authenticate-with-microsoft-entra-id
