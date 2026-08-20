# CKV_AZURE_71: Ensure that Managed identity provider is enabled for app services

## Severity
**LOW** (score: 2.0/10)

Lacking a managed identity forces app services to rely on hardcoded credentials or connection strings for accessing other Azure resources, weakening secrets hygiene but not by itself creating a direct exposure path.

## Summary
This check ensures an Azure App Service (Web App) has a managed identity (`identity` block/`identity/type`) configured, of any type, rather than relying solely on stored credentials for authenticating to other Azure resources.

## Applicability
- **Terraform**: `azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app`
- **ARM/Bicep**: `Microsoft.Web/sites`

## Why it matters
Without a managed identity, application code that needs to call other Azure services (Key Vault, Storage, SQL, Service Bus, etc.) must authenticate using long-lived secrets — client IDs/secrets, connection strings, or SAS tokens — usually stored in app settings or config files. These static credentials are a common source of breach: they get committed to source control, logged, cached in build artifacts, or exfiltrated if the app is compromised, and they don't expire on a predictable schedule tied to identity lifecycle. A managed identity lets Azure AD issue short-lived, automatically-rotated tokens scoped to the app's own identity, eliminating the need to provision, store, or rotate secrets for service-to-service auth, and it lets you use Azure RBAC to grant only the specific permissions the app needs.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `identity/[0]/type` (Terraform) or `identity/type` (ARM) attribute and expects `ANY_VALUE` — meaning the check passes as long as any `identity` block with any `type` (`SystemAssigned`, `UserAssigned`, or `SystemAssigned, UserAssigned`) is present. It fails if the `identity` block is absent entirely.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {}
  # no identity block -> app must use static credentials to reach other Azure services
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {}

  identity {
    type = "SystemAssigned"   # enables managed identity for the app
  }
}
```

## Remediation steps
1. Add an `identity { type = "SystemAssigned" }` block (or `UserAssigned`/both) to the app service resource.
2. Grant the resulting managed identity the least-privilege Azure RBAC roles it needs on downstream resources (e.g. `Key Vault Secrets User`, `Storage Blob Data Reader`).
3. Update application code to use `DefaultAzureCredential` (or the equivalent SDK identity chain) instead of connection strings/keys where feasible.
4. Remove now-unnecessary secrets from app settings once the identity-based access path is verified working.
5. Note: adding an identity block does not require resource replacement, but code changes to actually use the identity are a separate follow-up.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceIdentityProviderEnabled.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceIdentityProviderEnabled.py
- Azure docs: https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity
