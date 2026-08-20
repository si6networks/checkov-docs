# CKV_AZURE_224: Ensure that the Ledger feature is enabled on database that requires cryptographic proof and nonrepudiation of data integrity
## Severity
**MEDIUM** (score: 5.0/10)

Without the Ledger feature, tampering with database rows by a privileged user (including a DBA) leaves no cryptographically verifiable trail, weakening data-integrity assurance and forensic capability even though it does not itself prevent unauthorized access.

## Summary
Ensures that an Azure SQL Database has the Ledger feature enabled, which cryptographically protects historical data against tampering — including tampering by privileged users such as DBAs or cloud administrators.

## Applicability
- **Terraform**: `azurerm_mssql_database` — inspects `ledger_enabled`

## Why it matters
Traditional database access controls can prevent unauthorized external actors from modifying data, but they generally cannot protect against a trusted insider with sufficient privileges — a rogue DBA, a compromised administrative account, or a cloud provider-level actor — silently altering historical records (e.g., financial transactions, audit trails, compliance records) without leaving a detectable trace. Azure SQL Ledger addresses this by maintaining a cryptographically chained history of all changes to ledger tables: every insert/update/delete is recorded immutably, and the integrity of the entire history can be independently verified using cryptographic digests. Without this feature enabled, a database handling data subject to non-repudiation or tamper-evidence requirements (financial ledgers, chain-of-custody records, regulatory audit logs) has no built-in mechanism to detect or prove that historical records have not been altered — undermining forensic investigations and regulatory attestations that depend on trustworthy historical data.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `ledger_enabled` attribute of `azurerm_mssql_database`. The check **PASSES** when `ledger_enabled` is set to `true`; it **FAILS** when the attribute is `false` or left unset (the default is `false`).

Note the check's own source comments flag important operational caveats: Ledger must be enabled at database creation time and cannot be removed afterward, it may carry a measurable performance overhead, and it increases storage cost due to retained historical data.

## Non-compliant example
```hcl
resource "azurerm_mssql_database" "example" {
  name      = "example-db"
  server_id = azurerm_mssql_server.example.id
  sku_name  = "S0"

  # ledger_enabled left unset -> defaults to false
}
```

## Remediated example
```hcl
resource "azurerm_mssql_database" "example" {
  name           = "example-db"
  server_id      = azurerm_mssql_server.example.id
  sku_name       = "S0"
  ledger_enabled = true   # enable cryptographic tamper-evidence for this database
}
```

## Remediation steps
1. Set `ledger_enabled = true` when defining the `azurerm_mssql_database` resource.
2. Enable this **only at initial database creation** — the setting cannot be changed on an existing database, so an existing non-ledger database requires creating a new ledger-enabled database and migrating data (e.g., via export/import or a data migration pipeline), which is a non-trivial, potentially downtime-incurring operation.
3. Only enable Ledger for databases/workloads that genuinely need cryptographic tamper-evidence (financial systems, regulated audit data) given the associated performance overhead and increased storage cost from retained historical data — evaluate whether it's needed org-wide or only for specific high-sensitivity databases.
4. After enabling, establish a process to periodically run digest verification (via the ledger verification stored procedures/tools) to actually validate the integrity chain — enabling the feature alone does not automatically prove integrity unless verification is performed.
5. Monitor query and write latency after enabling Ledger in a staging environment before rolling out to production, to quantify the actual performance impact for your workload.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLDatabaseLedgerEnabled.py
- Azure docs: https://learn.microsoft.com/en-us/azure/azure-sql/database/ledger-overview
