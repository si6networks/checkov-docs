# CKV_AZURE_80: Ensure that 'Net Framework' version is the latest, if used as a part of the web app

## Severity
**LOW** (score: 2.0/10)

Running an outdated .NET Framework version leaves the web app exposed to known, patched vulnerabilities in the runtime rather than an active misconfiguration, so risk is contingent on which unpatched CVEs apply.

## Summary
This check ensures Azure App Service web apps running .NET Framework use a currently supported version — Checkov's current logic requires `v8.0`, `v9.0`, or `v10.0` — rather than an older, unsupported .NET version.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_app_service`, `azurerm_windows_web_app`
- **ARM/Bicep**: `Microsoft.Web/sites/config`

## Why it matters
Older .NET Framework/.NET runtime versions stop receiving security patches once they reach end-of-life. Running a web application on an unsupported runtime means any newly discovered vulnerability in the framework itself (deserialization flaws, request-parsing bugs, cryptographic weaknesses) will never be fixed for that app, leaving a permanent, unpatchable hole regardless of how well the application code is written. Since .NET Framework versions are periodically retired by Microsoft on a published support lifecycle, apps pinned to an old version silently drift out of the security-patch window over time even without any code change.

## How Checkov evaluates this
- **Terraform**: Looks at `site_config[0].dotnet_framework_version` and, for newer resource shapes, `site_config[0].application_stack[0].dotnet_version`. The value must be in the supported set `{"v8.0", "v9.0", "v10.0"}` to pass; anything else fails. If neither key is present in a usable form, the result is `UNKNOWN` rather than pass/fail.
- **ARM**: Inspects `properties/netFrameworkVersion` and expects exactly `"v8.0"`.

Note: the supported-version set is periodically updated in the Checkov source as Microsoft's .NET support lifecycle advances (e.g. v6.0 was removed after reaching EOL); check the current Checkov source for the exact accepted values at the time you run it.

## Non-compliant example
```hcl
resource "azurerm_windows_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    dotnet_framework_version = "v6.0"   # end-of-life runtime
  }
}
```

## Remediated example
```hcl
resource "azurerm_windows_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    application_stack {
      dotnet_version = "v8.0"   # currently supported LTS runtime
    }
  }
}
```

## Remediation steps
1. Identify the actual supported .NET Framework/.NET versions at deployment time from Microsoft's .NET support policy page, and set `dotnet_framework_version`/`application_stack.dotnet_version` accordingly.
2. Test the application against the newer runtime in a staging slot before switching production, since major version bumps (e.g. Framework 4.x to .NET 8) can involve breaking API changes.
3. Set up a recurring process (e.g. quarterly review) to track .NET's published EOL dates so the app is upgraded proactively rather than reactively.
4. Runtime version changes typically apply without resource replacement but do restart the app.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDotnetFrameworkVersion.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceDotnetFrameworkVersion.py
- Microsoft .NET support policy: https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core
