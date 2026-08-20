# CKV_AZURE_145: Ensure Function app is using the latest version of TLS encryption
## Severity
**HIGH** (score: 7.0/10)

Allowing a Function App to accept TLS versions below 1.2 permits use of weak/deprecated protocol versions with known cryptographic weaknesses, exposing data in transit to downgrade and interception attacks.

## Summary
This check ensures an Azure Function App (or its deployment slots) enforces a minimum TLS version of 1.2 (or higher) for inbound HTTPS connections, rather than allowing older, weaker TLS versions.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **ARM**: `Microsoft.Web/sites` and `Microsoft.Web/sites/slots` resources, property `properties/siteConfig/minTlsVersion`.
- **Terraform**: `azurerm_function_app`, `azurerm_function_app_slot`, `azurerm_linux_function_app`, `azurerm_linux_function_app_slot`, `azurerm_windows_function_app`, `azurerm_windows_function_app_slot` — attribute `site_config[0].min_tls_version` (older resource types) or `site_config[0].minimum_tls_version` (newer linux/windows resource types).

## Why it matters
TLS versions below 1.2 (TLS 1.0, TLS 1.1, and SSL) have known cryptographic weaknesses (e.g., BEAST, POODLE-adjacent issues, weak cipher suite support) and are deprecated by major browsers, PCI-DSS, and industry standards. Allowing clients to negotiate down to these older protocol versions exposes traffic to downgrade attacks and weaker encryption, particularly relevant for Function Apps that frequently serve as API backends, webhook receivers, or integration endpoints handling authentication tokens and business data. Enforcing a minimum of TLS 1.2 (with 1.3 also acceptable) ensures only modern, secure cipher suites and handshake protocols are used, closing off legacy-protocol attack vectors.

## How Checkov evaluates this
Both variants are `BaseResourceValueCheck`s. The Terraform version dynamically picks the attribute key based on resource type: `site_config/[0]/min_tls_version` for the older `azurerm_function_app`/`azurerm_function_app_slot`, or `site_config/[0]/minimum_tls_version` for the newer `azurerm_linux_function_app*`/`azurerm_windows_function_app*` types. The ARM version reads `properties/siteConfig/minTlsVersion`. Both accept any of `"1.2"`, `1.2`, `"1.3"`, `1.3` as PASSing values (via `get_expected_values`). Notably, both are constructed with `missing_block_result=CheckResult.PASSED` — if the `site_config`/`siteConfig` block is entirely absent, the check PASSES, because Azure's platform default for new Function Apps is already TLS 1.2, so no explicit setting is needed to be compliant by default. It only FAILS when the attribute is explicitly present and set to something older (e.g. `"1.0"` or `"1.1"`).

## Non-compliant example
```hcl
resource "azurerm_linux_function_app" "example" {
  name                       = "example-func"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  service_plan_id            = azurerm_service_plan.example.id

  site_config {
    minimum_tls_version = "1.0"  # FAILS -- deprecated, weak TLS version allowed
  }
}
```

## Remediated example
```hcl
resource "azurerm_linux_function_app" "example" {
  name                       = "example-func"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  service_plan_id            = azurerm_service_plan.example.id

  site_config {
    minimum_tls_version = "1.2"  # enforces modern TLS only
  }
}
```

## Remediation steps
1. Explicitly set `minimum_tls_version` (or `min_tls_version` for the legacy `azurerm_function_app` resource type) to `"1.2"` — omitting it entirely is also acceptable since the platform default is compliant, but explicit configuration is clearer and audit-friendly.
2. If you find an existing app explicitly pinned to `"1.0"` or `"1.1"` (often left from legacy client compatibility requirements), identify and upgrade any legacy clients/integrations that cannot negotiate TLS 1.2 before tightening this setting, to avoid breaking connectivity.
3. Consider `"1.3"` where fully supported by all consuming clients for the strongest available protocol version.
4. This is a configuration-only change (no resource replacement); it can be applied via a standard `terraform apply` without downtime.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/FunctionAppMinTLSVersion.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppMinTLSVersion.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-tls-versions
