# CKV_AZURE_72: Ensure that remote debugging is not enabled for app services

## Severity
**MEDIUM** (score: 5.0/10)

Remote debugging opens an additional network listener on the app service that can expose debugging interfaces and application internals, increasing the attack surface for unauthorized code execution or information disclosure.

## Summary
This check ensures Azure App Service (Web/Function apps and slots) do not have remote debugging enabled in `site_config`, since a missing setting defaults to disabled (pass), but an explicit `true` fails.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_app_service`, `azurerm_linux_function_app`, `azurerm_linux_function_app_slot`, `azurerm_linux_web_app`, `azurerm_linux_web_app_slot`, `azurerm_windows_function_app`, `azurerm_windows_function_app_slot`, `azurerm_windows_web_app`, `azurerm_windows_web_app_slot`
- **ARM/Bicep**: `Microsoft.Web/sites`

## Why it matters
Remote debugging opens a dedicated debugger port on the App Service that allows attaching Visual Studio or another remote debugger directly to the running production process. If left enabled, it significantly expands the attack surface: an attacker who can reach the debug endpoint (or who obtains valid publishing/debug credentials) can inspect live memory, set breakpoints, read variables containing secrets or customer data, and potentially execute arbitrary code in the context of the app. Debugging features are meant for short, deliberate troubleshooting sessions, not to be left on indefinitely in production.

## How Checkov evaluates this
`BaseResourceValueCheck` inspects `site_config/[0]/remote_debugging_enabled` (Terraform) or `properties/siteConfig/remoteDebuggingEnabled` (ARM) and expects the value `False`. The check is configured with `missing_block_result=CheckResult.PASSED`, so if the attribute or the whole `site_config` block is absent, it passes (remote debugging defaults to off). It only fails when the attribute is explicitly set to `true`.

## Non-compliant example
```hcl
resource "azurerm_windows_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    remote_debugging_enabled = true   # exposes a live debugger endpoint
  }
}
```

## Remediated example
```hcl
resource "azurerm_windows_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    remote_debugging_enabled = false   # or simply omit the attribute
  }
}
```

## Remediation steps
1. Set `remote_debugging_enabled = false` in `site_config`, or remove the attribute entirely so the default (disabled) applies.
2. If remote debugging is genuinely needed for troubleshooting, enable it temporarily via the Azure Portal/CLI outside of IaC, restrict access with IP restrictions/App Service access restrictions, and disable it again immediately afterward.
3. Prefer alternative diagnostics (Application Insights, log streaming, profiler snapshots) over live remote debugging in production.
4. This change takes effect without downtime/replacement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceRemoteDebuggingNotEnabled.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceRemoteDebuggingNotEnabled.py
- Azure docs: https://learn.microsoft.com/en-us/azure/app-service/configure-common
