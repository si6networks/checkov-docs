# CKV_AZURE_155: Ensure debugging is disabled for the App service slot

## Severity
**HIGH** (score: 7.5/10)

Leaving remote debugging enabled on an App Service slot exposes a live debugger port that, if reachable, can let an attacker inspect memory, extract secrets, or alter running application state.

## Summary
This check ensures that remote debugging is turned off on Azure App Service deployment slots, so a remote debugger port is not left open and reachable.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, Bicep, ARM
- **Resource types:**
  - Terraform: `azurerm_app_service_slot`
  - ARM/Bicep: `Microsoft.Web/sites`, `Microsoft.Web/sites/slots`

## Why it matters
Remote debugging opens a dedicated network port that allows a debugger client to attach directly to the running application process. If left enabled in non-development environments, this presents a significant attack surface: an attacker who can reach the debug endpoint (especially if it isn't tightly IP-restricted) can potentially inspect memory, set breakpoints, alter application state, extract secrets held in process memory (connection strings, tokens), or use the debug session as a foothold for further compromise. This is a classic "forgot to turn it off after troubleshooting" misconfiguration — most dangerous specifically because deployment slots (staging/canary) are used for that exact kind of ad-hoc troubleshooting and are then left in that debug-enabled state.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Terraform:** inspects `site_config[0].remote_debugging_enabled`.
- **ARM/Bicep:** inspects `properties.siteConfig.remoteDebuggingEnabled`.
- If the `site_config`/`siteConfig` block is missing entirely, the check **PASSES** (`missing_block_result=CheckResult.PASSED`) — remote debugging defaults to disabled.
- **PASS** if the value is explicitly `false`.
- **FAIL** if the value is `true`.

## Non-compliant example
```hcl
resource "azurerm_app_service_slot" "staging" {
  name                = "staging"
  app_service_name    = azurerm_app_service.example.name
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    remote_debugging_enabled = true   # remote debug port left open
  }
}
```

## Remediated example
```hcl
resource "azurerm_app_service_slot" "staging" {
  name                = "staging"
  app_service_name    = azurerm_app_service.example.name
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    remote_debugging_enabled = false   # remote debugging disabled
  }
}
```

## Remediation steps
1. Set `remote_debugging_enabled = false` (Terraform) or omit/`properties.siteConfig.remoteDebuggingEnabled: false` (ARM/Bicep) on every slot.
2. If remote debugging is genuinely needed for active troubleshooting, enable it temporarily and time-box the change (turn it back off once the session ends) rather than leaving it in IaC as permanently enabled.
3. Combine with network-level restrictions (access restrictions / IP allowlists) if remote debugging must be used, so the debug endpoint isn't exposed to the whole internet even temporarily.
4. This is an in-place configuration change, no resource replacement needed.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceSlotDebugDisabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceSlotDebugDisabled.py)
- [Azure App Service remote debugging documentation](https://learn.microsoft.com/en-us/azure/app-service/configure-common)
