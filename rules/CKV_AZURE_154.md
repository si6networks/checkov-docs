# CKV_AZURE_154: Ensure the App service slot is using the latest version of TLS encryption

## Severity
**MEDIUM** (score: 5.5/10)

Allowing an outdated minimum TLS version on an App Service slot weakens in-transit encryption and leaves the endpoint susceptible to protocol downgrade attacks, though exploitation still requires a network-level attacker.

## Summary
This check ensures that Azure App Service deployment slots enforce a minimum TLS version of 1.2 (or 1.3) for inbound connections, matching the hardening expected of production app services.

## Applicability
- **Framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_app_service_slot`

## Why it matters
Deployment slots inherit most of the parent app's runtime behavior but have their own independent `site_config`, meaning TLS settings are not automatically synced from production. If a slot is left at a default or explicitly lower minimum TLS version, it becomes a weaker link an attacker can target — for example, forcing a downgrade to TLS 1.0/1.1 to exploit known protocol weaknesses (POODLE, BEAST) and intercept or tamper with data in transit to the slot, even though the production slot itself is properly hardened. Since slots can carry near-production data (staging/canary swaps, pre-prod testing with real datasets), this is not merely a cosmetic gap.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects `site_config[0].min_tls_version`:
- If the `site_config` block is missing entirely, the check **PASSES** (`missing_block_result=CheckResult.PASSED`) — Azure's platform default is already TLS 1.2.
- **PASS** if `min_tls_version` is `"1.2"`, `1.2`, `"1.3"`, or `1.3`.
- **FAIL** if set to a lower value (e.g. `"1.0"` or `"1.1"`).

## Non-compliant example
```hcl
resource "azurerm_app_service_slot" "staging" {
  name                = "staging"
  app_service_name    = azurerm_app_service.example.name
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    min_tls_version = "1.0"   # deprecated, insecure TLS version on the slot
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
    min_tls_version = "1.2"   # enforces modern TLS on the slot
  }
}
```

## Remediation steps
1. Set `min_tls_version = "1.2"` (or `"1.3"`) in the `site_config` block of every `azurerm_app_service_slot` resource.
2. If migrating to newer resources (`azurerm_linux_web_app_slot` / `azurerm_windows_web_app_slot`), the attribute name is `minimum_tls_version` — set it the same way.
3. This is an in-place configuration change and does not require slot recreation.
4. Verify all client integrations calling into the slot support TLS 1.2+, especially older monitoring/test tooling that may target staging slots specifically.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceSlotMinTLS.py)
- [Azure App Service TLS/SSL documentation](https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings)
