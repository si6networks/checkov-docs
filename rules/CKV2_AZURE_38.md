# CKV2_AZURE_38: Ensure soft-delete is enabled on Azure storage account

## Severity
**LOW** (score: 2.0/10)

Missing soft-delete on a storage account is primarily an availability/recoverability gap (accidental or malicious blob deletion becomes unrecoverable) rather than a direct confidentiality or access-control failure.

## Summary
This check ensures an Azure Storage Account's blob service has soft-delete (delete retention policy) enabled with a positive retention period, so deleted blobs can be recovered within a window before permanent removal.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check)
- **Resource type:** `azurerm_storage_account`

## Why it matters
Without soft-delete, any blob deletion — whether from accidental user action, a buggy application/script, or a malicious actor with storage-account access (e.g., a compromised SAS token or leaked access key) — is immediate and irreversible. This is a common ransomware and data-destruction pattern: an attacker who gains write/delete access to a storage account can permanently destroy backups, logs, or production data with no recovery path. Soft-delete provides a safety net: deleted blobs are retained for a configurable number of days and can be undeleted, mitigating both accidental data loss and deliberate destructive attacks (though it does not protect against an attacker who also disables the soft-delete policy itself before deleting data).

## How Checkov evaluates this
Graph-based JSON policy over `azurerm_storage_account`. It PASSES when both conditions hold:
1. Blob soft-delete is configured: either `blob_properties.delete_retention_policy.days` is greater than 0, or the `blob_properties.delete_retention_policy` block simply exists (covering the case where `days` isn't explicitly set and Azure/provider defaults apply).
2. The storage account is not a `FileStorage` kind account (`account_kind` either doesn't exist, or is not `FileStorage`) — `FileStorage` accounts don't support blob soft-delete, so the check exempts them rather than failing.

If neither condition 1 is met (no `delete_retention_policy` block at all) for a non-FileStorage account, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # no blob_properties / delete_retention_policy configured at all
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  blob_properties {
    delete_retention_policy {
      days = 7   # enables soft-delete with a 7-day recovery window
    }
  }
}
```

## Remediation steps
1. Add a `blob_properties { delete_retention_policy { days = N } }` block to every `azurerm_storage_account` resource, where `N` is a positive integer (Azure allows 1-365 days).
2. Choose a retention period that balances recovery needs against storage cost for retained deleted blobs.
3. Also consider enabling container soft-delete (`container_delete_retention_policy`) and versioning for defense-in-depth against destructive operations.
4. Restrict who can modify the storage account's soft-delete settings via Azure RBAC, since an attacker with `Microsoft.Storage/storageAccounts/blobServices/write` could disable this protection before deleting data.
5. This does not apply to `FileStorage` kind accounts (Azure Files Premium) — Checkov exempts these automatically.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureStorageAccountEnableSoftDelete.json)
- [Azure Storage soft delete for blobs documentation](https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview)
