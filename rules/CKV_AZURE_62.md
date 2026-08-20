# CKV_AZURE_62: Ensure function apps are not accessible from all regions
## Severity
**LOW** (score: 2.0/10)

A wildcard CORS policy on Function Apps removes the browser's cross-origin protection for HTTP-triggered functions, letting an attacker-controlled site trigger requests and read responses via a victim's session.

## Summary
This check fails when an Azure Function App's CORS configuration allows all origins (`*`), which permits any website on the internet to make cross-origin browser requests to the function app's HTTP endpoints.

## Applicability
Applies to Terraform (`azurerm_function_app`), ARM templates, and Bicep, for the resource type `Microsoft.Web/sites`.

## Why it matters
Despite the "regions" wording in the policy title (a historical naming artifact — the underlying implementation is a CORS check), this rule is about Cross-Origin Resource Sharing on the Function App's HTTP triggers. A wildcard `allowedOrigins: "*"` tells browsers it is safe for any origin's JavaScript to read responses from the function app. If any HTTP-triggered function returns sensitive data, or relies on browser-attached credentials/cookies for a lightweight trust model, an attacker-controlled website can silently trigger the function from a victim's browser and read the response, enabling data exfiltration or abuse of the function on the victim's behalf. Function Apps often act as lightweight backend APIs for SPAs, so an open CORS policy effectively removes the browser-side access control that developers may be implicitly relying on.

## How Checkov evaluates this
This is a "negative value check" with `missing_block_result`/`missing_attribute_result` of PASSED — no CORS block at all is treated as compliant. When a CORS block exists, Checkov inspects `allowedOrigins` (`properties/siteConfig/cors/allowedOrigins` in ARM/Bicep, `site_config[0].cors[0].allowed_origins` in Terraform) and FAILS only if the list contains the forbidden value `"*"`. An explicit, non-wildcard origin list PASSES.

## Non-compliant example
```hcl
resource "azurerm_function_app" "example" {
  name                       = "example-function-app"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

  site_config {
    cors {
      allowed_origins = ["*"]
    }
  }
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

  site_config {
    cors {
      allowed_origins = ["https://app.example.com"]  # explicit trusted origin only
    }
  }
}
```

## Remediation steps
1. Replace the `["*"]` wildcard with an explicit list of trusted frontend origins that need to call this Function App.
2. If the function app has no browser-based consumers (e.g. it's called server-to-server or via API Management), remove the `cors` block entirely — the check treats a missing block as compliant, and CORS is irrelevant to non-browser callers.
3. Do not implement a "reflect the Origin header" workaround in application code; this is functionally equivalent to `*` and defeats the purpose of CORS restriction.
4. If migrating to `azurerm_linux_function_app`/`azurerm_windows_function_app`, apply the same `cors` restriction under `site_config`.
5. Re-verify legitimate integrations after narrowing the origin list.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/FunctionAppDisallowCORS.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppDisallowCORS.py)
- [MDN: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
