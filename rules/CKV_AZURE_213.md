# CKV_AZURE_213: Ensure that App Service configures health check
## Severity
**LOW** (score: 2.0/10)

Without a health check path, the platform cannot detect and route traffic away from unhealthy instances, creating an availability gap rather than a directly exploitable vulnerability.

## Summary
Ensures that an Azure App Service (Web App) defines a health-check path so Azure can monitor instance health and route traffic away from unhealthy instances.

## Applicability
- **Terraform**: `azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app` — inspects `site_config[0].health_check_path`
- **ARM**: `Microsoft.Web/sites`, `Microsoft.Web/sites/slots` — inspects `properties.siteConfig.healthCheckPath`
- **Bicep**: compiles to the ARM resource types above

## Why it matters
Azure App Service load-balances traffic across all instances behind an App Service Plan. Without a configured health-check path, Azure has no application-level signal to know whether a specific worker instance is actually able to serve requests correctly — it can only see gross failures like a completely crashed process. If an instance is degraded (e.g., a dependency like a database or cache is unreachable, but the process itself is still up and responding to the TCP socket), traffic keeps flowing to that broken instance, causing intermittent errors and timeouts for end users. Configuring a health-check path lets App Service periodically probe a specific endpoint that exercises real application logic and dependencies; unhealthy instances are automatically removed from the load-balancing rotation and replaced, improving overall availability and reducing user-facing errors.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using `ANY_VALUE` as the expected value — meaning any non-empty value configured for the health-check path attribute causes a **PASS**.
- **Terraform**: inspects `site_config/[0]/health_check_path`. If this key is absent or empty, the check **FAILS**.
- **ARM**: inspects `properties/siteConfig/healthCheckPath`. Same logic — absence causes **FAILED**.
There is no validation of the path's actual content, only that some path string has been set.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    # no health_check_path configured
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
    health_check_path = "/health"   # added health-check endpoint
  }
}
```

## Remediation steps
1. Implement a `/health` (or similarly named) endpoint in your application that performs a lightweight check of critical dependencies (database connectivity, cache, downstream APIs) and returns HTTP 200 only when the instance is genuinely healthy.
2. Set `site_config.health_check_path` (Terraform) or `properties.siteConfig.healthCheckPath` (ARM/Bicep) to that endpoint's path.
3. If running multiple instances, also consider setting `health_check_eviction_time_in_min` (Terraform, supported on newer `azurerm` provider versions) to control how quickly an unhealthy instance is evicted and how quickly it's restored once healthy again.
4. Ensure the health-check endpoint does not require authentication, or that the health-check prober is exempted from any auth middleware, otherwise Azure will interpret 401/403 responses as unhealthy.
5. Test the endpoint under failure conditions (e.g., simulate a downstream outage) to confirm it correctly reports unhealthy status.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceSetHealthCheck.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceSetHealthCheck.py
- Azure docs: https://learn.microsoft.com/en-us/azure/app-service/monitor-instances-health-check
