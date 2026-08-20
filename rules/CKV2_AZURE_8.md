# CKV2_AZURE_8: Ensure the storage container storing the activity logs is not publicly accessible

## Severity
**CRITICAL** (score: 9.0/10)

A publicly accessible storage container holding Azure activity logs can leak detailed operational and security-relevant metadata (and potentially secrets logged in activity data) to anyone on the internet, and can also let an attacker tamper with or erase evidence of their own actions.

## Summary
This check verifies that a storage container used to hold Azure Activity Log exports is not configured for public (blob/container) access, protecting the confidentiality of the audit trail itself.

## Applicability
- **Terraform**: `azurerm_storage_container` connected to an `azurerm_storage_account`, which in turn may be connected to an `azurerm_monitor_activity_log_alert`.

This is a graph-based connection/attribute check spanning three resource types.

## Why it matters
Activity logs record management-plane operations across your Azure subscription — who created, modified, or deleted resources, role assignments, network rule changes, and more. If the storage container holding these logs is publicly accessible, anyone on the internet can read your organization's operational history: which resources exist, naming conventions, IP ranges, personnel/service principal identifiers, and timing patterns useful for reconnaissance before an attack. Worse, depending on access type, a public container could allow tampering or deletion of logs, destroying the audit trail needed for incident response and compliance attestations (SOC 2, ISO 27001, etc.). Logs meant to detect and investigate compromise become a liability if they themselves are exposed.

## How Checkov evaluates this
Implemented as a JSON graph query with an `or` at the top level; the check passes if *either* branch of the `or` is satisfied. In practice this means it fails only in the specific combination where all of the following are true:
- The storage container has `container_access_type` set to something other than `"private"` (or, per the first branch's logic, the alerting-monitoring linkage condition is not otherwise satisfied) — i.e., **`container_access_type` must be `"private"` or absent (defaults to private) for the check to reliably pass.**
- The container is connected to a storage account, and that storage account either has no connected `azurerm_monitor_activity_log_alert`, or has one that is explicitly disabled (`enabled = false`).

In short: the check is primarily driven by `azurerm_storage_container.container_access_type` — it must be `"private"` (or unset) rather than `"blob"` or `"container"` for a container that is plausibly holding activity logs. FAIL occurs when `container_access_type` is `"blob"` or `"container"` (public) on a container associated with the activity-log storage account.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "logs" {
  name                     = "examplelogsstorage"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "activity_logs" {
  name                  = "activity-logs"
  storage_account_name  = azurerm_storage_account.logs.name
  container_access_type = "blob"   # FAILS: publicly readable
}

resource "azurerm_monitor_activity_log_alert" "example" {
  name                = "example-alert"
  resource_group_name = azurerm_resource_group.example.name
  scopes              = [data.azurerm_subscription.current.id]
  enabled             = true
  # ... criteria/action omitted
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "logs" {
  name                     = "examplelogsstorage"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "activity_logs" {
  name                  = "activity-logs"
  storage_account_name  = azurerm_storage_account.logs.name
  container_access_type = "private"   # fixed: no public access
}

resource "azurerm_monitor_activity_log_alert" "example" {
  name                = "example-alert"
  resource_group_name = azurerm_resource_group.example.name
  scopes              = [data.azurerm_subscription.current.id]
  enabled             = true
  # ... criteria/action omitted
}
```

## Remediation steps
1. Set `container_access_type = "private"` (or omit the attribute, since `"private"` is the default) on any storage container that receives Activity Log exports.
2. Enable Azure Storage's "Allow Blob public access" setting to `false` at the storage-account level (`allow_nested_items_to_be_public = false`) as a defense-in-depth measure, so no container under that account can be made public even by accident.
3. If activity log alerts are configured, ensure they remain `enabled = true` so that unexpected access or configuration changes are still surfaced.
4. Consider using a dedicated storage account exclusively for log exports with restrictive network rules (private endpoint or selected-networks firewall) in addition to disabling public container access.
5. Audit existing containers for `container_access_type` values of `"blob"` or `"container"` and correct them; changing access type does not require resource replacement.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/StorageContainerActivityLogsNotPublic.json)
- [Azure Storage anonymous access documentation](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure)
