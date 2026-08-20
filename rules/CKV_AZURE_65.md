# CKV_AZURE_65: Ensure that App service enables detailed error messages
## Severity
**LOW** (score: 2.0/10)

Detailed error logging is a server-side diagnostic setting that does not change what is exposed to end users or attackers; its absence only reduces operational/forensic visibility rather than closing an exploitable path.

## Summary
This check fails when an Azure App Service (or Web App) does not have detailed error message logging enabled, meaning verbose server-side error diagnostics for failed requests are not captured.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

Applies to Terraform (`azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app`), ARM templates, and Bicep, for the resource type `Microsoft.Web/sites/config`.

## Why it matters
Detailed error messages (`detailedErrorLoggingEnabled`) write full HTML error pages, including stack traces and configuration hints, to server-side log storage whenever a request fails with an HTTP error. This is a diagnostic/logging control, not something exposed to end users — Azure serves generic error pages externally regardless of this setting — so enabling it does not itself create an information-disclosure risk to attackers. Without it, however, operations and security teams investigating an outage or an attempted exploitation (e.g. a crafted request that triggers an unhandled exception, a probing attempt for a vulnerable endpoint that errors out) lose the detailed server-side context needed to understand what happened and why, slowing both troubleshooting and incident response. This complements HTTP logging and failed-request tracing as part of a complete diagnostic-logging baseline for internet-facing App Services.

## How Checkov evaluates this
- ARM/Bicep: inspects `properties/detailedErrorLoggingEnabled` on `Microsoft.Web/sites/config` and expects it to be truthy (the base `BaseResourceValueCheck` compares against its default expected value of `True`); false or missing FAILS.
- Terraform: inspects `logs[0].detailed_error_messages_enabled` (for `azurerm_app_service`) or `logs[0].detailed_error_messages` (for the newer `azurerm_linux_web_app`/`azurerm_windows_web_app`), expecting a truthy value; a missing `logs` block defaults to FAILED.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  service_plan_id     = azurerm_service_plan.example.id

  site_config {}
  # no logs block — detailed error messages are not captured
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
    detailed_error_messages = true  # captures server-side error diagnostics

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
1. Add a `logs` block to the App Service/Web App resource with `detailed_error_messages_enabled = true` (`azurerm_app_service`) or `detailed_error_messages = true` (`azurerm_linux_web_app`/`azurerm_windows_web_app`).
2. Ensure the captured detailed error logs are stored somewhere with adequate retention and access control — they can contain internal paths, stack traces, or configuration details, so restrict who can read them (they're not exposed externally by default, but treat the log store itself as sensitive).
3. Pair this with `http_logs` (CKV_AZURE_63) and `failed_request_tracing` (CKV_AZURE_66) for complete web-tier diagnostics.
4. No downtime or resource replacement is required — this is an in-place configuration update.
5. Periodically prune old detailed error logs per your retention/compliance policy since they can accumulate quickly under sustained error conditions.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceDetailedErrorMessagesEnabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDetailedErrorMessagesEnabled.py)
- [Azure docs: Enable diagnostics logging for apps in Azure App Service](https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs)
