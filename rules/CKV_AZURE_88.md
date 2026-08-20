# CKV_AZURE_88: Ensure that app services use Azure Files
## Severity
**LOW** (score: 2.0/10)

This check is about App Service using managed Azure Files storage for content persistence and consistency across scale-out instances, a reliability/operational concern rather than a direct security exposure.

## Summary
This check verifies that an Azure App Service (Web App) is configured with an Azure Files storage mount (`type == "AzureFiles"`) rather than relying purely on the ephemeral local file system.

## Applicability
- **Terraform**: `azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app` (inspects the `storage_account` block's `type` attribute)
- **ARM templates**: `Microsoft.Web/sites/config` (inspects `properties.azureStorageAccounts.<name>.type`)
- **Bicep**: resources compiling to `Microsoft.Web/sites/config`

## Why it matters
App Service instances (especially on the Windows/Linux Consumption or shared-plan tiers) run on infrastructure that can be reallocated, restarted, or scaled across multiple instances at any time. Content written only to local disk:
- Is lost on restart, scale-in, or platform-initiated instance moves, causing unexpected data loss for anything the app persists to disk (uploads, generated reports, logs meant for retention).
- Is not shared across scaled-out instances, so a multi-instance deployment can behave inconsistently if instances expect to read each other's on-disk state.
- Increases the operational/reliability risk profile: an app that "worked in testing" against a single always-warm instance can silently misbehave in production once autoscaling or platform maintenance kicks in.

Mounting an Azure Files share gives the app service a persistent, shared, network-backed file system so state survives instance churn and is consistent across all instances.

## How Checkov evaluates this
- **Terraform**: Uses `BaseResourceValueCheck` looking at `storage_account/[0]/type`, expecting the value `AzureFiles`. If the first `storage_account` block's `type` is not `AzureFiles` (or the block is absent), it fails.
- **ARM**: Reads `conf.properties.azureStorageAccounts`, which is a dict keyed by mount name. It iterates all entries — if **any** entry has `type == "AzureFiles"`, the check PASSES; if the whole `azureStorageAccounts` block is missing or none of the entries use `AzureFiles`, it FAILS.

## Non-compliant example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {}
  # no storage_account block -> no Azure Files mount
}
```

## Remediated example
```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {}

  storage_account {
    name         = "sharedstorage"
    type         = "AzureFiles"   # <-- persistent, shared storage mount
    account_name = azurerm_storage_account.example.name
    share_name    = azurerm_storage_share.example.name
    access_key    = azurerm_storage_account.example.primary_access_key
    mount_path    = "/mounts/shared"
  }
}
```

## Remediation steps
1. Provision an `azurerm_storage_account` and `azurerm_storage_share` (or reuse existing ones) for the app to persist data to.
2. Add a `storage_account` block to the web app resource with `type = "AzureFiles"`, pointing `account_name`, `share_name`, and `access_key` at that storage share.
3. Set an appropriate `mount_path` inside the container/app filesystem.
4. Re-deploy any application code that writes to local disk paths so it targets the new mount path instead.
5. Note this is primarily relevant for stateful workloads; purely stateless apps (which persist nothing meaningful to disk) may reasonably suppress this check if Azure Files genuinely adds no value.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceUsedAzureFiles.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppServiceUsedAzureFiles.py
