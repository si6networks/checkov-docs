# CKV_AZURE_66: Ensure that App service enables failed request tracing
## Severity
**LOW** (score: 2.0/10)

Failed request tracing is a diagnostic capability for reconstructing request-handling failures; lacking it slows incident investigation but does not itself create or widen an attack surface.

## Summary
This check fails when an Azure App Service (or Web App) does not have failed request tracing enabled, meaning detailed IIS-level tracing of failed requests is not captured for diagnostics.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

Applies to Terraform (`azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app`), ARM templates, and Bicep, for the resource type `Microsoft.Web/sites/config`.

## Why it matters
Failed request tracing captures a step-by-step trace of how IIS/the web server processed a request that resulted in an error, including module-level timing and state — much richer than a simple status-code log line. This is a critical diagnostic capability for both operational reliability and security investigations: it lets responders reconstruct exactly where a request failed (e.g. authentication module rejection, a module timing out due to resource exhaustion possibly from a DoS attempt, or an application error triggered by malformed/malicious input) rather than just knowing that it failed. Without this control, teams have significantly reduced visibility into the mechanics of failures during an incident, extending investigation time and potentially missing early indicators of an attack that manifests as elevated error rates before a full compromise is detected.

## How Checkov evaluates this
- ARM/Bicep: inspects `properties/requestTracingEnabled` on `Microsoft.Web/sites/config` and expects it to be truthy (the base check's default expected value); false or missing FAILS.
- Terraform: inspects `logs[0].failed_request_tracing_enabled` (for `azurerm_app_service`) or `logs[0].failed_request_tracing` (for `azurerm_linux_web_app`/`azurerm_windows_web_app`), expecting a truthy value; missing `logs` block or attribute FAILS.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  service_plan_id     = azurerm_service_plan.example.id

  site_config {}
  # no logs block — failed request tracing is disabled
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
    failed_request_tracing = true  # captures detailed traces for failed requests

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
1. Add a `logs` block with `failed_request_tracing_enabled = true` (`azurerm_app_service`) or `failed_request_tracing = true` (`azurerm_linux_web_app`/`azurerm_windows_web_app`).
2. Regularly review the generated trace logs (stored on the App Service file system by default) — they can grow large, so ensure retention/cleanup is managed to avoid filling the app's storage quota.
3. Combine with `http_logs` (CKV_AZURE_63) and `detailed_error_messages` (CKV_AZURE_65) to give responders the full picture: what happened (HTTP log), why it errored (detailed error message), and exactly where in the pipeline it failed (failed request trace).
4. No resource replacement is needed — this is a straightforward in-place `azurerm` configuration change.
5. Be aware failed request tracing is more relevant/available for Windows-based App Service plans; behavior on Linux plans may differ depending on the underlying stack.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceEnableFailedRequest.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceEnableFailedRequest.py)
- [Azure docs: Enable diagnostics logging for apps in Azure App Service](https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs)
