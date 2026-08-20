# CKV_AZURE_63: Ensure that App service enables HTTP logging
## Severity
**LOW** (score: 2.0/10)

Missing HTTP access logging removes the primary forensic record of requests to an internet-facing app, hampering incident response and detection of scanning or exploitation attempts without directly enabling an attack itself.

## Summary
This check fails when an Azure App Service (or Web App) does not have HTTP request logging enabled, meaning inbound HTTP traffic to the app is not recorded for later analysis.

## Applicability
Applies to Terraform (`azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app`), ARM templates, and Bicep, for the resource type `Microsoft.Web/sites/config`.

## Why it matters
HTTP logs (the IIS/web-server-style access logs) record request method, path, status code, client IP, user agent, and timing for every request hitting the app. Without them, security and operations teams lose their primary forensic artifact for investigating web-layer incidents: they cannot reconstruct an attacker's request sequence during an intrusion (e.g. identifying exploitation of a vulnerable endpoint, enumeration/scanning activity, or a web shell being accessed), cannot correlate a spike in 5xx errors or 401/403s with an attack, and cannot support compliance requirements that mandate access logging for internet-facing systems. HTTP logging is a low-cost, foundational detective control — its absence creates a blind spot that is most painful exactly when it's needed most: during incident response.

## How Checkov evaluates this
- ARM/Bicep: reads `properties/httpLoggingEnabled` on `Microsoft.Web/sites/config` and expects the boolean `true`; any other value (including `false` or missing) FAILS.
- Terraform: checks the `logs[0].http_logs` block is present with any value (`ANY_VALUE`) on the relevant App Service/Web App resources; if the `logs` block or `http_logs` sub-block is absent, it FAILS.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  service_plan_id     = azurerm_service_plan.example.id

  site_config {}
  # no logs block — HTTP request logging is not enabled
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  service_plan_id     = azurerm_service_plan.example.id

  site_config {}

  logs {
    http_logs {
      file_system {
        retention_in_mb   = 35
        retention_in_days = 7
      }
    }
  }
}
```

## Remediation steps
1. Add a `logs` block with `http_logs` (either `file_system` for local storage or `azure_blob_storage` to ship logs to a storage account for longer retention) to the App Service/Web App resource.
2. Prefer `azure_blob_storage` with a reasonable `retention_in_days` for durable, centralized log storage rather than relying solely on the local file system quota.
3. Route these logs (or the storage account/blob container they land in) into your SIEM or Log Analytics workspace for alerting and correlation, not just passive storage.
4. Confirm the app service plan tier supports the desired log volume/retention — very high traffic apps may need Blob storage rather than file-system logs to avoid quota exhaustion.
5. Combine with `detailed_error_messages` (CKV_AZURE_65) and `failed_request_tracing` (CKV_AZURE_66) for fuller diagnostic coverage.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceHttpLoggingEnabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHttpLoggingEnabled.py)
- [Azure docs: Enable diagnostics logging for apps in Azure App Service](https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs)
