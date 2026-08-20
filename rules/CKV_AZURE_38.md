# CKV_AZURE_38: Ensure audit profile captures all the activities

## Severity
**LOW** (score: 2.0/10)

If the Activity Log profile omits Write, Delete, or Action categories, security-relevant administrative operations across the subscription go unrecorded, blinding detection and response to malicious or unauthorized changes.

## Summary
This check verifies that an Azure Monitor Log Profile is configured to capture all three Activity Log event categories — `Write`, `Delete`, and `Action` — rather than a subset.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_monitor_log_profile`
- **ARM templates**: `Microsoft.Insights/logprofiles`
- **Bicep**: `Microsoft.Insights/logprofiles` (via the Terraform/ARM checks; same underlying resource)

## Why it matters
The Activity Log profile's `categories` field controls which classes of control-plane events are exported/retained: `Write` (create/update operations), `Delete` (resource deletions), and `Action` (other operations like restarts, role assignments invoked as actions). If a log profile only captures, say, `Write` and omits `Delete`, then an attacker or malicious insider who deletes a resource, storage account, or security control leaves no corresponding record in the exported/retained log — defeating incident response and forensic reconstruction. Auditors and compliance frameworks (e.g., CIS Azure Foundations Benchmark) specifically call out capturing all three categories, because a partial audit trail creates blind spots that are trivial for an attacker to exploit (e.g., delete evidence, then rely on the fact that deletions weren't logged).

## How Checkov evaluates this
- **ARM**: Reads `properties.categories`. PASSES only if all three of `"Write"`, `"Delete"`, and `"Action"` are present in the list. Missing any one of them FAILS.
- **Terraform**: Reads the `categories` attribute (a list). PASSES only if it is a non-empty list containing all three of `"Write"`, `"Delete"`, `"Action"`. Any omission FAILS.

## Non-compliant example
```hcl
resource "azurerm_monitor_log_profile" "example" {
  name = "default"

  categories = ["Write", "Action"]

  locations = ["eastus", "westus"]

  retention_policy {
    enabled = true
    days    = 365
  }
}
```

## Remediated example
```hcl
resource "azurerm_monitor_log_profile" "example" {
  name = "default"

  categories = ["Write", "Delete", "Action"]

  locations = ["eastus", "westus"]

  retention_policy {
    enabled = true
    days    = 365
  }
}
```

## Remediation steps
1. Locate the `azurerm_monitor_log_profile` (or `Microsoft.Insights/logprofiles`) resource.
2. Set `categories` to include all three values: `["Write", "Delete", "Action"]`.
3. Combine with CKV_AZURE_37 (365-day-or-greater retention) so the full event set is both captured and retained long enough to be useful.
4. If your subscription has migrated to the newer Diagnostic Settings model (recommended by Microsoft going forward), configure the equivalent log categories on `azurerm_monitor_diagnostic_setting` at the subscription scope instead.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/MonitorLogProfileCategories.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MonitorLogProfileCategories.py)
- [Azure Activity Log event categories](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema)
