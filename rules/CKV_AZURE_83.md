# CKV_AZURE_83: Ensure that 'Java version' is the latest, if used to run the web app

## Severity
**LOW** (score: 2.0/10)

An outdated Java runtime may lack fixes for known JVM/library vulnerabilities, posing a latent patching risk rather than an immediate exposure.

## Summary
This check ensures Azure App Service web apps configured to run Java use a current, supported Java version rather than an outdated one.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_app_service`
- **ARM/Bicep**: `Microsoft.Web/sites`

## Why it matters
Java runtimes (OpenJDK/Zulu builds distributed via App Service) receive security updates on a defined support schedule, and older major versions eventually stop being patched. A web app pinned to an outdated Java version misses fixes for JVM-level vulnerabilities (deserialization gadget chains, TLS/crypto library flaws, JIT compiler bugs), some of which have historically enabled remote code execution. Since the Java runtime version is a platform setting independent of application code changes, apps commonly drift onto unsupported Java versions unnoticed until an audit or scan flags it.

## How Checkov evaluates this
- **ARM**: Inspects `siteConfig/javaVersion` and expects the value `"17"`. If the field is missing, the result is `UNKNOWN` (Java may not be in use for that app).
- **Terraform**: Inspects `site_config/[0]/java_version/[0]` and expects `"11"` in this implementation, again with `missing_block_result=CheckResult.UNKNOWN`.

The two implementations currently target different Java LTS versions (17 vs 11); in practice, aim for whichever is the newest LTS Java version Azure App Service supports at deploy time.

## Non-compliant example
```hcl
resource "azurerm_app_service" "example" {
  name                = "example-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    java_version = "1.8"   # outdated Java version
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
    java_version = "17"   # current supported Java LTS version
  }
}
```

## Remediation steps
1. Check `az webapp list-runtimes --os linux` (or the Portal runtime picker) for the Java versions currently supported by Azure App Service, and choose the newest LTS release.
2. Update `site_config.java_version` accordingly.
3. Test thoroughly in staging — Java major version upgrades (e.g. 8 to 17) can involve removed APIs (e.g. `javax.*` -> `jakarta.*` in some frameworks) and JVM behavior changes.
4. Track Java's LTS release/support cadence to plan proactive upgrades; this change restarts the app but does not require resource replacement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceJavaVersion.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceJavaVersion.py
- Azure App Service Java docs: https://learn.microsoft.com/en-us/azure/app-service/configure-language-java
