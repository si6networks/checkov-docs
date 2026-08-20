# CKV_AZURE_81: Ensure that 'PHP version' is the latest, if used to run the web app

## Severity
**LOW** (score: 2.0/10)

An outdated PHP runtime can carry known, unpatched interpreter-level vulnerabilities, but exploitability depends on the specific version gap and application exposure rather than an immediate open attack path.

## Summary
This check ensures Azure App Service web apps configured to run PHP use a current, supported PHP version rather than an outdated one.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_app_service`
- **ARM/Bicep**: `Microsoft.Web/sites`

## Why it matters
PHP versions reach end-of-life on a regular cadence, after which the PHP project stops shipping security fixes. A web app still configured with an EOL PHP version has no vendor patch path for any newly disclosed PHP interpreter vulnerability (e.g. memory corruption in extensions, deserialization issues), which is a direct route to remote code execution on the hosting App Service if exploited. Because PHP configuration is a simple site setting, apps are easily left on their original version for years after deployment, quietly drifting out of the support window.

## How Checkov evaluates this
- **ARM**: Inspects `properties/siteConfig/phpVersion` and accepts `"8.1"` or `"8.2"` as passing values; anything else fails. If the block is missing, the result is `UNKNOWN` (not a definite pass/fail) — the check can't assume PHP isn't in use.
- **Terraform**: Inspects `site_config/[0]/php_version/[0]` and expects the value `"7.4"` (an older accepted value in this implementation) — again with `missing_block_result=CheckResult.UNKNOWN` if the field is absent.

Note the ARM and Terraform variants of this check currently accept different exact version strings; treat the ARM values (8.1/8.2) as the more current guidance and prefer the latest PHP version Azure App Service supports at deploy time regardless of which exact string an older Checkov build expects.

## Non-compliant example
```hcl
resource "azurerm_app_service" "example" {
  name                = "example-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    php_version = "5.6"   # long end-of-life PHP version
  }
}
```

## Remediated example
```hcl
resource "azurerm_app_service" "example" {
  name                = "example-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    php_version = "8.2"   # current supported PHP version
  }
}
```

## Remediation steps
1. Check the current list of PHP runtimes Azure App Service supports (`az webapp list-runtimes --os linux` or the Portal's runtime stack picker) and pick the newest supported version.
2. Set `site_config.php_version` to that version.
3. Test the application against the newer PHP major version in staging first — major PHP version bumps (5.x to 8.x) commonly break deprecated syntax and removed extensions.
4. Establish a recurring review so PHP version stays current as new EOLs are announced; this is a config-only change with no resource replacement, though it restarts the app.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServicePHPVersion.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServicePHPVersion.py
- PHP supported versions: https://www.php.net/supported-versions.php
