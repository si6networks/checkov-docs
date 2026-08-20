# CKV_AZURE_128: Ensure that PostgreSQL server enables Threat detection policy
## Severity
**LOW** (score: 2.0/10)

Without threat detection, suspicious database access patterns and potential SQL injection attempts against the PostgreSQL server go unnoticed, delaying response to a real compromise of sensitive data.

## Summary
This check verifies that an Azure Database for PostgreSQL server has its Advanced Threat Protection (threat detection policy) enabled, so anomalous or potentially malicious database activity is automatically detected and alerted on.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_postgresql_server`

## Why it matters
Database servers are prime targets for both external attackers and malicious insiders because they hold the application's persistent, high-value data. Azure's threat detection for PostgreSQL monitors for SQL injection patterns, unusual data extraction volumes, brute-force login attempts, logins from anomalous locations, and access from IP addresses associated with known malicious activity, then raises alerts so the security team can respond in near real time. Without this enabled, a live compromise — for example an application-layer SQL injection vulnerability being actively exploited, or a leaked/brute-forced admin credential being used to dump a table — has no automated detection mechanism and may go unnoticed until the resulting data breach surfaces independently (e.g. via a dark-web leak), by which time the response is purely reactive.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `threat_detection_policy[0].enabled` attribute:
- **PASS** if `threat_detection_policy[0].enabled = true`.
- **FAIL** if the attribute/block is absent or set to `false`.

Note: `azurerm_postgresql_server` (single-server deployment model) is Microsoft's legacy PostgreSQL offering, now deprecated in favor of `azurerm_postgresql_flexible_server`, which uses Microsoft Defender for Cloud plans instead of this specific resource attribute for threat detection.

## Non-compliant example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "psql-example"
  location             = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladminun"
  administrator_login_password = var.admin_password
  sku_name                     = "GP_Gen5_2"
  version                      = "11"

  ssl_enforcement_enabled = true
  # no threat_detection_policy block -> no anomaly alerting
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "psql-example"
  location             = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladminun"
  administrator_login_password = var.admin_password
  sku_name                     = "GP_Gen5_2"
  version                      = "11"

  ssl_enforcement_enabled = true

  threat_detection_policy {
    enabled              = true
    email_account_admins = true
    storage_endpoint     = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key = azurerm_storage_account.example.primary_access_key
  }
}
```

## Remediation steps
1. Add a `threat_detection_policy` block with `enabled = true` to the `azurerm_postgresql_server` resource.
2. Set `email_account_admins = true` (and/or `email_addresses`) so security alerts reach the correct team.
3. Configure `storage_endpoint`/`storage_account_access_key` to persist detailed detection records for forensic follow-up.
4. If you are already on (or migrating to) `azurerm_postgresql_flexible_server`, note this specific attribute doesn't apply — instead enable Microsoft Defender for Cloud's plan for open-source relational databases, which covers the flexible server offering.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgresSQLTreatDetectionEnabled.py)
- [Azure Database for PostgreSQL threat detection documentation](https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-security)
