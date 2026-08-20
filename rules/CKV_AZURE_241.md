# CKV_AZURE_241: Ensure Synapse SQL pools are encrypted

## Severity
**LOW** (score: 2.0/10)

Disabling transparent data encryption on Synapse SQL pools leaves potentially sensitive analytical data unencrypted at rest, exposing it if underlying storage or backups are ever accessed improperly.

## Summary
This check ensures Azure Synapse dedicated SQL pools have Transparent Data Encryption (TDE) enabled via the `data_encrypted` attribute.

## Applicability
- **Terraform**: `azurerm_synapse_sql_pool` resources — inspects the `data_encrypted` attribute.

## Why it matters
Without Transparent Data Encryption, the underlying data and log files of a Synapse SQL pool are stored on disk in plaintext. If an attacker gains access to the physical storage layer, a backup file, or a database file left in an unencrypted state through some form of media theft, misconfigured backup export, or unauthorized access to storage infrastructure, the data is immediately readable without needing to compromise database credentials. TDE encrypts data at rest at the storage-engine level so that files, backups, and log data are unreadable outside of the database's paired encryption key. This is a baseline defense-in-depth control for regulated data (PII, financial data, health records) required by many compliance regimes (PCI-DSS, HIPAA) and is usually costless from a performance/operations perspective since it's transparent to applications.

## How Checkov evaluates this
`BaseResourceCheck` on `azurerm_synapse_sql_pool`. The check PASSES only if the `data_encrypted` key is present in config AND its value is exactly `True`; it FAILS if the key is absent or set to `false`.

## Non-compliant example
```hcl
resource "azurerm_synapse_sql_pool" "example" {
  name                 = "examplesqlpool"
  synapse_workspace_id = azurerm_synapse_workspace.example.id
  sku_name             = "DW100c"
  create_mode          = "Default"
  # data_encrypted not set -> defaults to false, FAILS
}
```

## Remediated example
```hcl
resource "azurerm_synapse_sql_pool" "example" {
  name                 = "examplesqlpool"
  synapse_workspace_id = azurerm_synapse_workspace.example.id
  sku_name             = "DW100c"
  create_mode          = "Default"
  data_encrypted       = true   # <-- TDE enabled, PASSES
}
```

## Remediation steps
1. Set `data_encrypted = true` on the `azurerm_synapse_sql_pool` resource.
2. Note that enabling TDE on an existing, populated SQL pool triggers a background encryption scan of existing data, which can take time proportional to data volume and consume additional compute/IO during the transition — plan for this on large pools.
3. If your organization requires customer-managed keys for TDE (rather than Microsoft-managed), configure the corresponding CMK settings at the parent Synapse workspace level (see CKV_AZURE_240) since dedicated SQL pool TDE keys are typically inherited from the workspace-level encryption configuration.
4. Verify this setting for every `azurerm_synapse_sql_pool` in the workspace — it's set per-pool, not workspace-wide.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SynapseSQLPoolDataEncryption.py
- Azure docs: https://learn.microsoft.com/en-us/azure/synapse-analytics/sql-data-warehouse/sql-data-warehouse-overview-manage-security#transparent-data-encryption-for-dedicated-sql-pool
