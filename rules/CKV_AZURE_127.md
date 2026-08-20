# CKV_AZURE_127: Ensure that My SQL server enables Threat detection policy
## Severity
**LOW** (score: 2.0/10)

Disabling threat detection removes automated alerting on anomalous database activity such as SQL injection or brute-force login attempts, delaying detection of an active compromise of a sensitive data store.

## Summary
This check verifies that an Azure Database for MySQL server has its Advanced Threat Protection (threat detection policy) enabled, so anomalous or potentially malicious database activity is automatically detected and alerted on.

## Applicability
- **IaC framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_mysql_server`

## Why it matters
Database servers are high-value targets: they hold the application's data at rest and are a common objective of both external attackers (via SQL injection or stolen credentials) and insider threats. Azure's threat detection for MySQL monitors for anomalous access patterns — SQL injection attempts, unusual data access volumes, logins from anomalous locations, brute-force login attempts, and access from known-malicious IPs — and generates alerts so security teams can respond quickly. Without threat detection enabled, an active attack against the database (e.g. a SQL injection exploiting an application vulnerability, or a compromised credential being used to exfiltrate data) can go entirely unnoticed until damage is already done, since ordinary database logs are rarely proactively monitored for these specific anomaly signatures.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `threat_detection_policy[0].enabled` attribute:
- **PASS** if `threat_detection_policy[0].enabled = true`.
- **FAIL** if the attribute/block is absent or set to `false` (default resource-value-check behavior for a missing block is FAIL since no `missing_block_result` override is specified).

Note: `azurerm_mysql_server` (single-server deployment model) is a legacy/deprecated Azure MySQL offering; newer deployments should use `azurerm_mysql_flexible_server`, which uses a different (Azure Defender for open-source relational databases) mechanism not covered by this specific check.

## Non-compliant example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "mysql-example"
  location             = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mysqladminun"
  administrator_login_password = var.admin_password
  sku_name                     = "GP_Gen5_2"
  version                      = "5.7"

  ssl_enforcement_enabled = true
  # no threat_detection_policy block -> no anomaly alerting
}
```

## Remediated example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "mysql-example"
  location             = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mysqladminun"
  administrator_login_password = var.admin_password
  sku_name                     = "GP_Gen5_2"
  version                      = "5.7"

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
1. Add a `threat_detection_policy` block with `enabled = true` to the `azurerm_mysql_server` resource.
2. Set `email_account_admins = true` (and/or `email_addresses`) so alerts reach the right people.
3. Configure `storage_endpoint`/`storage_account_access_key` so detailed detection records are stored for later analysis.
4. If you're already on (or planning to migrate to) `azurerm_mysql_flexible_server`, note that threat detection there is managed via Microsoft Defender for Cloud plans instead of this resource attribute — plan your migration path accordingly since single-server MySQL is retired/being retired by Microsoft.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLTreatDetectionEnabled.py)
- [Azure Database for MySQL threat detection documentation](https://learn.microsoft.com/en-us/azure/mysql/single-server/concepts-security)
