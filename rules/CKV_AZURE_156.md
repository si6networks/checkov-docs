# CKV_AZURE_156: Ensure default Auditing policy for a SQL Server is configured to capture and retain the activity logs

## Severity
**LOW** (score: 2.0/10)

Disabling or misconfiguring SQL Server auditing removes the activity log trail needed to detect and investigate unauthorized access or data manipulation on a sensitive database, undermining post-incident response and breach detection.

## Summary
This check ensures that Azure SQL Database extended auditing policies have `log_monitoring_enabled` set, so that audit logs are actively sent to Azure Monitor / Log Analytics for centralized capture and retention rather than only stored locally in a storage account.

## Applicability
- **Framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_mssql_database_extended_auditing_policy`

## Why it matters
Database audit logs are critical forensic and detective-control data — they record who accessed what data, when, and how, which is essential for detecting data exfiltration, unauthorized privilege use, or insider threats, and for meeting compliance retention requirements (SOC 2, PCI-DSS, HIPAA). If auditing is configured but not wired into centralized log monitoring (e.g. left as storage-account-only, or the monitoring flag disabled), logs can become fragmented, harder to correlate with other security telemetry, easier to miss during an active incident, and more likely to be overlooked/rotated out before an investigation begins. Enabling log monitoring ensures audit events flow into the organization's centralized detection and alerting pipeline.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects `log_monitoring_enabled`:
- **FAIL** if the attribute is missing (`missing_block_result=CheckResult.FAILED`).
- **FAIL** if explicitly set to `false`.
- **PASS** only if explicitly set to `true`.

## Non-compliant example
```hcl
resource "azurerm_mssql_database_extended_auditing_policy" "example" {
  database_id            = azurerm_mssql_database.example.id
  storage_endpoint        = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

  # log_monitoring_enabled omitted -> defaults to unmonitored, check FAILS
}
```

## Remediated example
```hcl
resource "azurerm_mssql_database_extended_auditing_policy" "example" {
  database_id                = azurerm_mssql_database.example.id
  storage_endpoint            = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key  = azurerm_storage_account.example.primary_access_key
  log_monitoring_enabled      = true   # sends audit logs to Azure Monitor
}
```

## Remediation steps
1. Add `log_monitoring_enabled = true` to every `azurerm_mssql_database_extended_auditing_policy` resource.
2. Ensure a Log Analytics workspace or Azure Monitor diagnostic setting is in place to actually receive and retain these logs long-term (this attribute enables monitoring integration, but retention policy/workspace configuration should be verified separately).
3. Set an appropriate `retention_in_days` value on the audit policy (or storage account lifecycle policy) to satisfy your organization's compliance retention window.
4. This is an in-place configuration change and does not affect the underlying database.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MSSQLServerAuditPolicyLogMonitor.py)
- [Azure SQL Database auditing documentation](https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview)
