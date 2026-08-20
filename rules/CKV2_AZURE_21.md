# CKV2_AZURE_21: Ensure Storage logging is enabled for Blob service for read requests
## Severity
**LOW** (score: 2.0/10)

Missing read-request logging for Blob service limits forensic visibility into access patterns but is not itself an exploitable misconfiguration.

## Summary
This check verifies that a non-public (private or blob-scoped) Azure Storage Container is linked, through its parent storage account, to a Log Analytics storage-insights configuration that captures Blob-service read logs.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check)
- **Resource types involved:** `azurerm_storage_container`, `azurerm_storage_account`, `azurerm_log_analytics_storage_insights`

## Why it matters
Blob containers commonly hold sensitive files — backups, documents, application artifacts, exported datasets. Without read-request logging, there is no way to detect or investigate unauthorized reads, whether from a leaked SAS token, an over-permissioned managed identity, or a misconfigured public endpoint. Blob-level access logs are a foundational control for detecting data exfiltration, satisfying regulatory audit requirements, and reconstructing a timeline during incident response. The check restricts itself to containers with `container_access_type` of `private` or `blob` — these are the containers where access control (and therefore the need to audit who read what) actually matters, as opposed to fully public/anonymous containers governed differently.

## How Checkov evaluates this
This is a **graph-based** check evaluating a chain of connections and attributes:
1. The `azurerm_storage_container` must have a graph connection to its `azurerm_storage_account`.
2. That storage account must have a graph connection to an `azurerm_log_analytics_storage_insights` resource.
3. The storage-insights resource must define the `blob_container_names` attribute.
4. The container's `container_access_type` attribute must be one of `private` or `blob` (the condition scopes evaluation to these access levels).
5. The final filter scopes PASS/FAIL to `azurerm_storage_container` resources.

Any container satisfying access-type `private`/`blob` but missing the storage-insights connection (or missing `blob_container_names`) FAILS.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = "example-rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "example" {
  name                  = "example-container"
  storage_account_name  = azurerm_storage_account.example.name
  container_access_type = "private"
}

# No azurerm_log_analytics_storage_insights resource — blob reads are unaudited.
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

resource "azurerm_storage_container" "example" {
  name                  = "example-container"
  storage_account_name  = azurerm_storage_account.example.name
  container_access_type = "private"
}

resource "azurerm_log_analytics_workspace" "example" {
  name                = "example-law"
  location            = "eastus"
  resource_group_name = "example-rg"
  sku                 = "PerGB2018"
}

# Added: storage insights capturing blob container read requests.
resource "azurerm_log_analytics_storage_insights" "example" {
  name                = "example-storageinsightconfig"
  resource_group_name = "example-rg"
  workspace_id        = azurerm_log_analytics_workspace.example.id
  storage_account_id  = azurerm_storage_account.example.id
  storage_account_key = azurerm_storage_account.example.primary_access_key

  blob_container_names = [azurerm_storage_container.example.name]
}
```

## Remediation steps
1. Provision an `azurerm_log_analytics_workspace` if one does not already exist.
2. Add an `azurerm_log_analytics_storage_insights` resource pointed at the storage account, with `blob_container_names` listing every container requiring auditing.
3. Confirm all affected containers use `container_access_type` of `private` or `blob` as intended for your data sensitivity — fully public containers should generally be avoided regardless of this check.
4. Re-run Checkov to confirm the graph connections resolve (all three resources must be visible in the same Terraform configuration/module graph).
5. Route the resulting logs to a SIEM and alert on abnormal read volumes or access from unexpected principals/IP ranges.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/StorageLoggingIsEnabledForBlobService.json)
- [Azure Storage Analytics logging](https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics-logging)
