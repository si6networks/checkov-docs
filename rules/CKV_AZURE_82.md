# CKV_AZURE_82: Ensure that 'Python version' is the latest, if used to run the web app

## Severity
**LOW** (score: 2.0/10)

Running an unsupported Python version risks missing security patches for the language runtime, a latent risk rather than a directly exploitable misconfiguration.

## Summary
This check ensures Azure App Service web apps configured to run Python use a current, supported Python interpreter version rather than an outdated one.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_app_service`
- **ARM/Bicep**: `Microsoft.Web/sites`

## Why it matters
Each Python minor version series is supported by the Python core team for a fixed window, after which it stops receiving security patches. Running a web app on an EOL Python interpreter means known vulnerabilities in the interpreter or standard library (e.g. in `ssl`, `urllib`, pickling/deserialization) will never be fixed for that app. Since the interpreter version is a platform-level App Service setting separate from application code, it's easy for an app to keep running on an old interpreter for years after its Python version stops being maintained, silently increasing the attack surface with every newly disclosed CVE in that unsupported branch.

## How Checkov evaluates this
- **ARM**: Inspects `properties/siteConfig/pythonVersion` and accepts `"3.9"`, `"3.10"`, `"3.11"`, or `"3.12"` as passing values. If the site config block for Python version is missing entirely, the result is `UNKNOWN` (the check can't tell whether Python is even in use).
- **Terraform**: Inspects `site_config/[0]/python_version/[0]` and expects the value `"3.4"` in this implementation — an older accepted value — again with `missing_block_result=CheckResult.UNKNOWN`.

As with the PHP check, prefer targeting the newest Python version Azure App Service currently supports (matching the ARM check's 3.9–3.12 range or later) rather than relying on the older Terraform-side expected value.

## Non-compliant example
```hcl
resource "azurerm_app_service" "example" {
  name                = "example-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    python_version = "2.7"   # end-of-life Python interpreter
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
    python_version = "3.12"   # current supported Python version
  }
}
```

## Remediation steps
1. Check `az webapp list-runtimes --os linux` (or the Portal runtime picker) for the current list of Python versions Azure App Service supports and choose the newest.
2. Update `site_config.python_version` accordingly.
3. Run the app's test suite against the new interpreter version in a staging slot first — Python major/minor version bumps can change standard library behavior and deprecate syntax.
4. Track Python's published end-of-life schedule and plan version bumps proactively rather than reactively; this is a configuration-only change that restarts the app but does not require resource replacement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServicePythonVersion.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServicePythonVersion.py
- Python release schedule (PEP 602/status): https://devguide.python.org/versions/
