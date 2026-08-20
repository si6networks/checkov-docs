# CKV_AZURE_33: Ensure Storage logging is enabled for Queue service for read, write and delete requests

## Severity
**LOW** (score: 2.0/10)

Missing read/write/delete logging on the Storage Queue service limits the ability to detect and investigate unauthorized access to queued messages, a monitoring gap on a moderately sensitive data path.

## Summary
This check ensures diagnostic logging is enabled and captures read, write, and delete operations for the Azure Storage Account's Queue service.

## Applicability
- **Frameworks:** Terraform, ARM, Bicep (via shared entities)
- **Resource types:** `Microsoft.Storage/storageAccounts/queueServices/providers/diagnosticsettings`, `azurerm_storage_account` (via its `queue_properties.logging` block; only relevant when `account_kind` is `Storage` or `StorageV2`)

## Why it matters
The Queue service is often used for decoupled/asynchronous application workflows and can carry messages containing task metadata, references to sensitive resources, or occasionally sensitive payload data directly. Without read/write/delete logging enabled, there is no audit trail of who accessed, modified, or deleted queue messages — making it impossible to detect unauthorized access, investigate data loss (e.g., messages deleted by a compromised identity or a bug), or satisfy compliance requirements that mandate storage-service activity logging. Comprehensive read+write+delete coverage (rather than just one operation type) ensures the full lifecycle of queue data access is auditable.

## How Checkov evaluates this
**ARM check**: inspects a `diagnosticsettings` resource's `properties.logs` array. For each log entry with `category` and `enabled` set, it tracks which categories are enabled. **PASS** only if all three categories — `StorageRead`, `StorageWrite`, `StorageDelete` — are present and each has `enabled` (case-insensitive) equal to `"true"`. **FAIL** otherwise (including if `properties` or `logs` is missing/empty).

**Terraform check**: first checks `account_kind` — if it's set and is neither `Storage` nor `StorageV2`, the check **auto-PASSes** (queue properties don't apply to other account kinds, e.g., BlobStorage). Otherwise it looks at `queue_properties[0].logging[0]` and requires `delete`, `write`, and `read` to all be truthy. **FAIL** if the logging block is missing or any of the three flags is false/absent.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"

  queue_properties {
    logging {
      delete                = false
      read                  = false
      write                 = true
      version               = "1.0"
      retention_policy_days = 10
    }
  }
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"

  queue_properties {
    logging {
      delete                = true   # was false
      read                  = true   # was false
      write                 = true
      version               = "1.0"
      retention_policy_days = 10
    }
  }
}
```

## Remediation steps
1. Add a `queue_properties.logging` block on the `azurerm_storage_account` resource with `delete = true`, `read = true`, and `write = true`.
2. For ARM/Bicep, add a `diagnosticsettings` resource under `Microsoft.Storage/storageAccounts/queueServices` with `properties.logs` entries for `StorageRead`, `StorageWrite`, and `StorageDelete`, each with `enabled = true`.
3. Set an appropriate `retention_policy_days` (or route logs to a Log Analytics workspace/Storage Account/Event Hub) so logs are retained long enough for your incident-response and compliance window.
4. This check only applies to `Storage`/`StorageV2` account kinds — general-purpose v2 and legacy general-purpose v1 accounts; other kinds (e.g., `BlobStorage`, `FileStorage`) don't expose classic queue logging in the same way.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountLoggingQueueServiceEnabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/StorageAccountLoggingQueueServiceEnabled.py)
- [Azure Storage Analytics logging](https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics-logging)
