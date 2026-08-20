# CKV2_AZURE_47: Ensure storage account is configured without blob anonymous access

## Severity
**MEDIUM** (score: 5.0/10)

Failing to block nested-item anonymous access lets any blob container in the account be flipped to public read, a common real-world exposure vector for sensitive files with no authentication required at all.

## Summary
This check ensures an Azure Storage Account explicitly disallows nested items (blobs/containers) from being configured for anonymous public read access.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check)
- **Resource type:** `azurerm_storage_account`

## Why it matters
Even when a storage account itself requires authentication by default, Azure allows individual blob containers to be set to `Blob` or `Container` public access level, making their contents readable by anyone with the URL, with no authentication at all. This is one of the most common real-world cloud data-exposure vectors — sensitive files (backups, exported databases, credentials, PII) end up in a container that a well-meaning developer flipped to "public" for convenience (e.g., to serve static assets) and forgot to revert, or that was created public by default in older tooling. Setting `allow_nested_items_to_be_public = false` at the account level is a hard guardrail: it prevents any container within the account from ever being set to public access, regardless of what an individual container's configuration says or what a future administrator attempts, closing off this entire class of accidental exposure at the account scope.

## How Checkov evaluates this
Graph-based JSON policy over `azurerm_storage_account`. PASSES only when both hold:
1. `allow_nested_items_to_be_public` attribute exists.
2. It equals `"false"` (case-insensitive).

If the attribute is missing (the Azure/provider default is actually `true`, permitting public access at the container level) or explicitly set to `true`, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # allow_nested_items_to_be_public not set -> defaults to true, containers can be made public
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

  allow_nested_items_to_be_public = false   # blocks any container/blob from ever being set to public access
}
```

## Remediation steps
1. Set `allow_nested_items_to_be_public = false` on every `azurerm_storage_account` resource.
2. Audit existing containers for any with `container_access_type = "blob"` or `"container"` and remediate — these will start rejecting anonymous requests once the account-level setting is applied (Azure will actually block the container-level public setting from being enforced).
3. For workloads that genuinely require public content delivery (e.g., static websites, public downloads), use Azure CDN/Front Door with SAS tokens or a dedicated, clearly-labeled public storage account instead of allowing anonymous access broadly.
4. This is a non-disruptive setting to enable unless something is actively relying on anonymous blob access — verify with access logs before enforcing in production.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureStorageAccConfigWithoutBlobAnonymousAccess.json)
- [Azure Storage: Remediate anonymous read access documentation](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent)
