# CKV_AZURE_78: Ensure FTP deployments are disabled

## Severity
**HIGH** (score: 7.5/10)

Enabling unencrypted FTP deployment on an app service allows credentials and deployed application code/artifacts to be transmitted and intercepted in cleartext, potentially enabling account takeover or code tampering.

## Summary
This check ensures Azure App Service's FTP/FTPS deployment state is set to `Disabled` or `FtpsOnly` — never left allowing plain unencrypted FTP.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app`
- **ARM/Bicep**: `Microsoft.Web/sites`

## Why it matters
FTP is a legacy protocol that transmits credentials and file contents in cleartext. App Service's FTP deployment endpoint, if enabled in unencrypted mode, lets anyone who can intercept network traffic (or brute-force the FTP credentials) capture the app's deployment username/password and then upload arbitrary files directly into the site's wwwroot — effectively achieving remote code execution by dropping a web shell. Even in the encrypted `FtpsOnly` case, FTP-based deployment is a broad, credential-based access path to the app's file system that bypasses whatever CI/CD controls, code review, or audit trail your normal deployment pipeline provides, so many organizations disable it entirely once a modern deployment method (Git, ZIP deploy over HTTPS, container-based deploy) is in use.

## How Checkov evaluates this
`BaseResourceValueCheck` inspects `site_config/0/ftps_state` (Terraform) or `properties/siteConfig/ftpsState` (ARM). Checkov accepts either `"Disabled"` or `"FtpsOnly"` as passing values (via `get_expected_values`); the primary expected value is `"Disabled"`. Any other value — notably `"AllAllowed"` (which permits plain FTP) or a missing attribute — fails.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    ftps_state = "AllAllowed"   # permits plain-text FTP
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
    ftps_state = "Disabled"   # or "FtpsOnly" if FTP-based deploy is still required
  }
}
```

## Remediation steps
1. Set `ftps_state = "Disabled"` in `site_config` if FTP deployment is not used.
2. If FTP-based deployment is still required for a legacy workflow, set `ftps_state = "FtpsOnly"` instead, which forces TLS-encrypted FTPS and rejects plain FTP.
3. Migrate deployment workflows to Git-based, ZIP/run-from-package, or container-based deployment through HTTPS as a longer-term fix, then fully disable FTP.
4. This setting can be changed on an existing app without downtime or replacement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceFTPSState.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceFTPSState.py
- Azure docs: https://learn.microsoft.com/en-us/azure/app-service/deploy-ftp
