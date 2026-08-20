# CKV_AZURE_214: Ensure App Service is set to be always on
## Severity
**LOW** (score: 2.0/10)

Disabling Always On only affects cold-start performance and request timeouts for idle apps, a hygiene/reliability concern with no meaningful direct attack surface.

## Summary
Ensures that an Azure App Service Web App has the "Always On" setting enabled so the app is not unloaded due to idle timeouts.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_linux_web_app`, `azurerm_windows_web_app` — inspects `site_config[0].always_on`

## Why it matters
By default, Azure App Service unloads (idles out) an app after a period of inactivity to conserve shared resources on the App Service Plan. The next incoming request after an idle period then triggers a "cold start," which reinitializes the application runtime, re-establishes database connections, JIT-compiles code, warms caches, etc. This produces noticeably slower response times and can cause request timeouts for the unlucky request that triggers the cold start — a real availability and user-experience problem, especially for latency-sensitive or externally-facing services. It is also required for apps that use Continuous WebJobs or CRON-triggered WebJobs, since those background jobs only run reliably while the app is loaded; without Always On, scheduled jobs can silently fail to fire. The "Always On" feature works by having the App Service load balancer periodically ping the application root, keeping it warm.

## How Checkov evaluates this
Terraform check inspects `site_config/[0]/always_on/[0]`. Notably, `missing_block_result=CheckResult.PASSED` is set — meaning if `always_on` is not explicitly specified at all, Checkov treats the check as **PASSED** (because Azure's default is `true` for supported SKUs). The check only **FAILS** when `always_on` is explicitly set to `false`.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    always_on = false
  }
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    always_on = true   # keep the app warm and avoid cold starts
  }
}
```

## Remediation steps
1. Set `site_config.always_on = true` explicitly, or simply omit the attribute (the check treats a missing value as passing since Azure defaults it to enabled where the SKU supports it).
2. Verify your App Service Plan SKU supports Always On — the `Free` (F1) and `Shared` (D1) tiers do not support it; use at least `Basic` (B1) or higher.
3. Be aware Always On keeps at least one instance permanently running, which has a cost/resource implication versus scale-to-zero patterns — this is an intentional tradeoff for availability.
4. If your app uses Continuous or CRON-triggered WebJobs, confirm Always On is enabled, since those jobs depend on it to run reliably.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceAlwaysOn.py
- Azure docs: https://learn.microsoft.com/en-us/azure/app-service/configure-common
