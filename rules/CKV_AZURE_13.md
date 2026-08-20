# CKV_AZURE_13: Ensure App Service Authentication is set on Azure App Service
## Severity
**LOW** (score: 2.0/10)

Disabling built-in App Service authentication removes the platform-enforced identity check in front of the application, potentially leaving the app's endpoints fully open to unauthenticated access from the internet.

## Summary
This check verifies that Azure App Service (Web App) has built-in authentication ("Easy Auth" / App Service Authentication) enabled, so requests to the app are authenticated at the platform level before reaching application code.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **IaC frameworks:** Terraform, ARM templates, Bicep
- **Resource types:**
  - Terraform: `azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app` (checks both the legacy `auth_settings` block and the modern `auth_settings_v2` block)
  - ARM: `Microsoft.Web/sites/config` and the standalone `config` sub-resource type (specifically the `authsettings` config, parented under `Microsoft.Web/sites`)

## Why it matters
App Service Authentication ("Easy Auth") provides a platform-level authentication gate that runs in the App Service sandbox before any request reaches your application's code, supporting identity providers like Azure AD, Google, Facebook, and generic OpenID Connect. When this is disabled, authentication (if any) must be implemented entirely in application code, which is a common source of vulnerabilities: forgotten unauthenticated routes, inconsistent enforcement across endpoints, custom auth logic with subtle bugs, or entirely missing authentication on an app that was assumed to be "internal only." Relying on Easy Auth for public-facing or internal apps ensures a consistent, platform-enforced authentication boundary that isn't dependent on every developer correctly wiring up auth middleware in every code path — closing off unauthenticated access to management endpoints, debug routes, or newly added pages that a developer forgot to protect.

## How Checkov evaluates this
The check logic differs by framework/entity but centers on whether authentication is turned on:
- **ARM**, entity `Microsoft.Web/sites/config`: PASS if the resource's `name` contains `"authsettings"` and `properties.enabled` is the string `"true"` (case-insensitive).
- **ARM**, entity `config` (nested resource): PASS if `name == "authsettings"`, `parent_type == "Microsoft.Web/sites"`, and `properties.enabled` is `"true"`; returns `UNKNOWN` if the entity type doesn't match either recognized shape.
- **Terraform**: checks two possible blocks in order —
  - `auth_settings[0].enabled` — PASS if truthy, FAIL if present but falsey.
  - if that's absent, `auth_settings_v2[0].auth_enabled` — PASS if truthy, FAIL if present but falsey.
  - FAIL if neither block is present at all.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "app-example"
  location             = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  service_plan_id     = azurerm_service_plan.example.id

  site_config {}
  # no auth_settings or auth_settings_v2 block -> no platform-level authentication
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "app-example"
  location             = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  service_plan_id     = azurerm_service_plan.example.id

  site_config {}

  auth_settings {
    enabled                       = true
    default_provider              = "AzureActiveDirectory"
    unauthenticated_client_action = "RedirectToLoginPage"

    active_directory {
      client_id = azuread_application.example.application_id
    }
  }
}
```

## Remediation steps
1. Add an `auth_settings` block (or the newer `auth_settings_v2` block with `auth_enabled = true`) to the App Service resource.
2. Configure at least one identity provider (Azure AD is typical for enterprise apps) with the appropriate client ID/tenant configuration.
3. Set `unauthenticated_client_action` to `"RedirectToLoginPage"` (for browser-based apps) or `"AllowAnonymous"` only for routes that should genuinely remain public — note Easy Auth applies at the app level, so if you need mixed public/private routes you may need to combine it with in-app authorization logic.
4. For ARM/Bicep, define the nested `config` resource named `authsettings` under the site with `properties.enabled: true` and the relevant identity provider settings.
5. This setting can generally be applied to an existing App Service without downtime, but test that legitimate unauthenticated health-check endpoints (if any) still function as expected after enabling.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceAuthentication.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceAuthentication.py)
- [Azure App Service authentication and authorization documentation](https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization)
