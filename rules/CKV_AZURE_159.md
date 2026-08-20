# CKV_AZURE_159: Ensure function app builtin logging is enabled

## Severity
**LOW** (score: 2.0/10)

Missing built-in logging on a function app reduces visibility into application behavior and potential abuse, but the impact is a monitoring gap rather than a direct exposure of data or access.

## Summary
This check ensures that Azure Function Apps (and their deployment slots) have built-in logging (`enable_builtin_logging`) turned on, so function invocation logs are captured by default.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (Azure provider)
- **Resource types:** `azurerm_function_app`, `azurerm_function_app_slot`

## Why it matters
Function Apps are frequently used to implement event-driven business logic, webhooks, and integrations that touch sensitive data or perform privileged actions (e.g., processing payments, calling internal APIs with elevated credentials). Without built-in logging, invocation details — errors, execution traces, and diagnostic information — may not be captured at all, which severely hampers incident response and forensics: if a function is abused (e.g., invoked with malicious input, used to probe backend systems, or exploited via a code vulnerability), there may be no record of what happened. Built-in logging (backed by Azure Storage, and integrable with Application Insights) provides the baseline observability needed to detect anomalies and investigate incidents after the fact.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects `enable_builtin_logging`:
- If the attribute is missing entirely, the check **PASSES** (`missing_block_result=CheckResult.PASSED`) — the Terraform azurerm provider defaults this to `true`.
- **PASS** if explicitly set to `true`.
- **FAIL** if explicitly set to `false`.

## Non-compliant example
```hcl
resource "azurerm_function_app" "example" {
  name                       = "example-func"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

  enable_builtin_logging = false   # invocation logs are not captured
}
```

## Remediated example
```hcl
resource "azurerm_function_app" "example" {
  name                       = "example-func"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

  enable_builtin_logging = true   # invocation logs captured to storage
}
```

## Remediation steps
1. Set `enable_builtin_logging = true` (or simply remove the attribute, since the provider default is `true`) on every `azurerm_function_app` / `azurerm_function_app_slot` resource.
2. For richer diagnostics beyond built-in logging, also integrate Application Insights (`application_insights_key` / `app_settings["APPINSIGHTS_INSTRUMENTATIONKEY"]`) for structured telemetry and distributed tracing.
3. Ensure the storage account backing built-in logging has an appropriate retention/lifecycle policy so logs aren't lost prematurely.
4. This is an in-place configuration change, no resource replacement required.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppEnableLogging.py)
- [Azure Functions monitoring documentation](https://learn.microsoft.com/en-us/azure/azure-functions/functions-monitoring)
