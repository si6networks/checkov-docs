# CKV_AZURE_16: Ensure that Register with Azure Active Directory is enabled on App Service

## Severity
**MEDIUM** (score: 5.0/10)

Without a managed identity, an App Service is more likely to rely on long-lived static credentials embedded in configuration to reach dependent services, increasing the risk of credential leakage and standing access if those secrets are exposed.

## Summary
This check ensures that an Azure App Service (Web App) has a managed identity (system-assigned or user-assigned) configured, so it is registered with Azure Active Directory (Entra ID) and can authenticate to other Azure resources without embedded credentials.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, Bicep, ARM
- **Resource types:**
  - Terraform: `azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app`
  - ARM/Bicep: `Microsoft.Web/sites`

## Why it matters
Without a managed identity, applications commonly authenticate to dependent services (Key Vault, Storage, SQL, other APIs) using long-lived static secrets — connection strings, API keys, or service principal credentials — stored in app settings, config files, or a secrets manager. These static credentials are a persistent liability: they can be leaked via logs, source control, or misconfigured app settings, they don't rotate automatically, and if compromised they typically grant standing access until manually revoked. A managed identity (backed by Azure AD) lets the App Service authenticate using short-lived, automatically-rotated tokens issued by the platform, with access governed by Azure RBAC — eliminating the need to manage and protect static secrets for that authentication path entirely.

## How Checkov evaluates this
**Terraform** (`BaseResourceValueCheck` with `ANY_VALUE`):
- Inspects the `identity` block.
- **PASS** if `identity` is present with any value (any identity configuration counts).
- **FAIL** if `identity` is absent.

**ARM/Bicep** (custom `BaseResourceCheck`):
- Looks at `conf["identity"]["type"]`.
- **PASS** if `type == "SystemAssigned"`.
- **PASS** if `type == "UserAssigned"` and `userAssignedIdentities` is present and non-empty.
- **FAIL** otherwise (missing `identity`, missing `type`, or `UserAssigned` with no identities specified).

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  # no identity block -> app must use static credentials to access other Azure resources

  site_config {}

  app_settings = {
    "STORAGE_CONNECTION_STRING" = "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=..."
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

  identity {
    type = "SystemAssigned"   # registers the app with Azure AD, enabling token-based auth
  }

  site_config {}
}
```

## Remediation steps
1. Add an `identity` block with `type = "SystemAssigned"` (simplest, tied to the resource lifecycle) or `"UserAssigned"` with a populated `identity_ids` (Terraform) / `userAssignedIdentities` (ARM/Bicep) referencing a pre-created managed identity.
2. Grant the identity the minimum necessary Azure RBAC roles (or Key Vault access policies) on the target resources it needs to reach.
3. Update application code to use the Azure Identity SDK (`DefaultAzureCredential` or platform-specific managed identity credential) instead of static connection strings/keys.
4. Remove static secrets from `app_settings` once the managed identity path is validated end-to-end.
5. This is an in-place, non-disruptive change; system-assigned identities are automatically deleted if the resource is deleted, while user-assigned identities persist independently.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceIdentity.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceIdentity.py)
- [Azure App Service managed identity documentation](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity)
