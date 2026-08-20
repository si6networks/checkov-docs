# CKV2_AZURE_20: Ensure Storage logging is enabled for Table service for read requests
## Severity
**LOW** (score: 2.0/10)

Missing read-request logging for Table service reduces audit visibility but does not itself expose data or create an exploitable access path.

## Summary
This check verifies that every Azure Storage Table is linked, through its parent storage account, to a Log Analytics storage-insights configuration that captures read-request logs for the Table service.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check)
- **Resource types involved:** `azurerm_storage_table`, `azurerm_storage_account`, `azurerm_log_analytics_storage_insights`

## Why it matters
Azure Table storage is frequently used to hold application state, session data, or lightweight NoSQL records, and read access to it is a common target for data-exfiltration attempts (leaked SAS tokens, compromised connection strings, over-privileged managed identities). Without Table-service read logging enabled, there is no audit trail showing who queried which entities and when. In an incident response scenario, the security team would be unable to determine whether data was accessed, by which principal, or how much data was read — making it impossible to scope a breach, satisfy compliance requirements (e.g., PCI-DSS, HIPAA access logging), or detect ongoing reconnaissance/exfiltration activity in near-real time.

## How Checkov evaluates this
This is a **graph-based** check (a JSON connection query, not a Python resource check). Checkov's graph builder resolves resource references (e.g., a `storage_account_name` field pointing to an `azurerm_storage_account`) into graph edges, then evaluates:
1. An `azurerm_storage_table` must have a graph connection to an `azurerm_storage_account` (i.e., the table must actually belong to a storage account resource in the configuration).
2. That same `azurerm_storage_account` must have a graph connection to an `azurerm_log_analytics_storage_insights` resource.
3. The `azurerm_log_analytics_storage_insights` resource must define the `table_names` attribute (indicating Table service logs are being collected).
4. The final `filter` clause scopes the PASS/FAIL result to the `azurerm_storage_table` resources.

If any table lacks this full chain (table → account → storage insights with `table_names` set), the check FAILS for that table.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = "example-rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_table" "example" {
  name                 = "exampletable"
  storage_account_name = azurerm_storage_account.example.name
}

# No azurerm_log_analytics_storage_insights resource is defined,
# so table read requests are never logged.
```

## Remediated example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = "example-rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_table" "example" {
  name                 = "exampletable"
  storage_account_name = azurerm_storage_account.example.name
}

resource "azurerm_log_analytics_workspace" "example" {
  name                = "example-law"
  location             = "eastus"
  resource_group_name  = "example-rg"
  sku                 = "PerGB2018"
}

# Added: storage insights configuration linking the account to Log
# Analytics and explicitly enumerating the table to be logged.
resource "azurerm_log_analytics_storage_insights" "example" {
  name                = "example-storageinsightconfig"
  resource_group_name = "example-rg"
  workspace_id        = azurerm_log_analytics_workspace.example.id
  storage_account_id  = azurerm_storage_account.example.id
  storage_account_key = azurerm_storage_account.example.primary_access_key

  table_names = [azurerm_storage_table.example.name]
}
```

## Remediation steps
1. Create (or reuse) an `azurerm_log_analytics_workspace` to receive the logs.
2. Add an `azurerm_log_analytics_storage_insights` resource referencing the storage account's `storage_account_id` and `storage_account_key`.
3. Populate the `table_names` attribute with the names of every table whose read requests must be audited.
4. Re-run `terraform plan`/`checkov` to confirm the graph connection is detected — the table, account, and storage-insights resources must all be declared in scope that Checkov can traverse (same root module or properly referenced modules).
5. Consider forwarding these logs to a SIEM or configuring alerts on anomalous read volume for early breach detection.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/StorageLoggingIsEnabledForTableService.json)
- [Azure Storage Analytics logging](https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics-logging)
