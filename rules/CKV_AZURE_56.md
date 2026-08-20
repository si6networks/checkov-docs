# CKV_AZURE_56: Ensure that function apps enables Authentication
## Severity
**LOW** (score: 2.0/10)

Disabling platform-level authentication on a Function App leaves publicly reachable HTTP-triggered code paths open to unauthenticated invocation, which can lead to data exposure, abuse of connected identities, or denial-of-wallet attacks.

## Summary
This check fails when an Azure Function App does not have App Service Authentication ("EasyAuth") enabled, meaning HTTP-triggered functions may be invokable without any identity check enforced by the platform.

## Applicability
Applies to Terraform (`azurerm_function_app`), ARM templates, and Bicep, for the resource type `Microsoft.Web/sites/config` (specifically the `authsettingsV2` config child resource).

## Why it matters
Function Apps frequently expose HTTP endpoints that trigger business logic, access backend data stores, or call other internal services. If App Service Authentication is not enabled, the only thing standing between the public internet and function execution is whatever auth logic the function code itself implements (often none, or a weak API key in a query string). This creates a direct risk of unauthenticated invocation, enabling attackers to trigger expensive operations (denial-of-wallet/DoS via serverless billing), access data the function reads, or abuse the function as a pivot into connected resources (e.g. via a managed identity with broader permissions than intended). Platform-level authentication (Azure AD, or another identity provider) provides a centrally-managed, consistently-enforced gate in front of the function that isn't dependent on the function code doing the right thing.

## How Checkov evaluates this
- ARM/Bicep: only evaluates resources named `authsettingsV2`. For those, it checks `properties.platform.enabled`; if `enabled` is truthy, PASS, otherwise FAIL. Resources not named `authsettingsV2` are automatically PASSED (not the intended check target).
- Terraform: inspects the `auth_settings` block's first element's `enabled` attribute (`auth_settings/[0]/enabled`) on `azurerm_function_app`; if not explicitly set to a truthy value, FAILS.

## Non-compliant example
```hcl
resource "azurerm_function_app" "example" {
  name                       = "example-function-app"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

  # no auth_settings block — authentication is not enforced
}
```

## Remediated example
```hcl
resource "azurerm_function_app" "example" {
  name                       = "example-function-app"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

  auth_settings {
    enabled                       = true
    default_provider               = "AzureActiveDirectory"
    unauthenticated_client_action  = "RedirectToLoginPage"

    active_directory {
      client_id = var.aad_client_id
    }
  }
}
```

## Remediation steps
1. Add an `auth_settings` block with `enabled = true` to the `azurerm_function_app` resource.
2. Configure a default identity provider (Azure AD is recommended for first-party apps) and set `unauthenticated_client_action` appropriately (e.g. `RedirectToLoginPage` for browser flows, or reject with 401 for API-only functions).
3. If migrating to the newer `azurerm_linux_function_app`/`azurerm_windows_function_app` resources, use the `auth_settings_v2` block instead, which maps to the ARM `authsettingsV2` config.
4. Combine platform auth with function-level authorization (`authLevel`) where fine-grained control is still needed — EasyAuth is a coarse gate, not a replacement for app-level authorization logic.
5. Test that existing anonymous integrations (webhooks, callbacks from third parties) still function after enabling auth, or explicitly exclude those routes.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/FunctionAppsEnableAuthentication.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppsEnableAuthentication.py)
- [Azure docs: Authentication and authorization in Azure App Service and Azure Functions](https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization)
