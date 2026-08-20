# CKV_AZURE_67: Ensure that 'HTTP Version' is the latest, if used to run the Function app
## Severity
**LOW** (score: 2.0/10)

Running an older but still-supported HTTP version is a protocol hygiene/best-practice item with no direct exploitable path of its own, since HTTP/1.1 is not inherently insecure.

## Summary
This check fails when an Azure Function App does not have HTTP/2 enabled in its site configuration, leaving the app running on the older HTTP/1.1 protocol.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

Applies to Terraform (`azurerm_function_app`, `azurerm_function_app_slot`), ARM templates, and Bicep, for the resource types `Microsoft.Web/sites` and `Microsoft.Web/sites/slots`.

## Why it matters
HTTP/2 provides performance improvements (multiplexing, header compression, prioritization) but is also relevant from a security-hygiene perspective: staying on the latest supported protocol version ensures the app benefits from ongoing platform-level improvements and reduces the likelihood of relying on legacy protocol handling paths in the underlying web server stack that receive less security attention over time. While HTTP/1.1 itself is not inherently "insecure," using the latest supported HTTP version aligns with the general principle of minimizing exposure to deprecated protocol implementations, and it is treated by cloud providers' own security baselines (including Azure Security Benchmark) as a best-practice configuration check for App Service/Function App workloads.

## How Checkov evaluates this
- ARM/Bicep: inspects `properties/siteConfig/http20Enabled` on `Microsoft.Web/sites` and `Microsoft.Web/sites/slots`, using the base check's default expected value of `True`; false or missing FAILS.
- Terraform: inspects `site_config[0].http2_enabled` on `azurerm_function_app`/`azurerm_function_app_slot`, again expecting a truthy default; false or missing FAILS.

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
    http2_enabled = false
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
    http2_enabled = true  # use the latest supported HTTP protocol version
  }
}
```

## Remediation steps
1. Set `site_config.http2_enabled = true` (Terraform) or `properties.siteConfig.http20Enabled: true` (ARM/Bicep) on the Function App resource.
2. Verify any HTTP client libraries used to call the function (or by the function itself when calling out) support HTTP/2, though this setting only controls inbound protocol negotiation to the function app and clients will gracefully fall back if unsupported.
3. This is an in-place configuration change with no downtime typically required.
4. If migrating to the newer `azurerm_linux_function_app`/`azurerm_windows_function_app` resources, set the equivalent `application_stack`/`site_config.http2_enabled` there.
5. Re-test any legacy monitoring/APM agents that specifically parse HTTP/1.1-style traffic, as behavior/format may differ slightly under HTTP/2.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/FunctionAppHttpVersionLatest.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppHttpVersionLatest.py)
- [Azure docs: Configure an App Service app](https://learn.microsoft.com/en-us/azure/app-service/configure-common)
