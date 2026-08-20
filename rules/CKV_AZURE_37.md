# CKV_AZURE_37: Ensure that Activity Log Retention is set 365 days or greater

## Severity
**LOW** (score: 2.0/10)

Insufficient Activity Log retention shortens the historical window available for forensic investigation and compliance review of subscription-level control-plane actions, an availability-of-evidence gap rather than an active exposure.

## Summary
This check verifies that an Azure Monitor Log Profile retains the subscription's Activity Log for at least 365 days (or indefinitely, via a retention setting of `0` days), rather than expiring logs sooner.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_monitor_log_profile`
- **ARM templates**: `Microsoft.Insights/logprofiles`
- **Bicep**: `Microsoft.Insights/logprofiles`

## Why it matters
The Azure Activity Log records subscription-level control-plane events — who created, modified, or deleted resources, role assignments, and policy changes. It is the primary forensic trail for incident response and compliance audits (e.g., PCI-DSS, ISO 27001, SOC 2 commonly require a minimum of a year of audit-log retention). If retention is set too low (e.g., 30 or 90 days), evidence of an intrusion or unauthorized change can silently expire before an investigation even begins — many breaches aren't detected for months. A retention value of `0` in Azure means "retain indefinitely," which also satisfies this control; anything else below 365 leaves a compliance and forensic gap.

## How Checkov evaluates this
- **ARM**: Reads `properties.retentionPolicy`. PASSES only if `enabled` is (case-insensitively) `"true"` AND `days` is present and is either `0` (unlimited) or `>= 365`. Anything else (missing retention policy, disabled policy, or a retention period between 1–364 days) FAILS.
- **Terraform**: Reads the `retention_policy` block. If the block is missing entirely, FAIL. If `retention_policy[0].enabled` is true, it PASSES only when `days >= 365`. If `enabled` is false, it PASSES if `days == 0` or if `days` isn't specified at all (interpreted as unlimited retention since the policy is effectively disabled/unbounded) — otherwise if `enabled` is false with any other day value it still returns PASSED (the check treats a disabled retention policy as "logs are never purged"). In practice, always explicitly set `enabled = true` with `days >= 365` to be unambiguous.

## Non-compliant example
```hcl
resource "azurerm_monitor_log_profile" "example" {
  name = "default"

  categories = ["Action", "Delete", "Write"]

  locations = ["eastus", "westus"]

  retention_policy {
    enabled = true
    days    = 90
  }
}
```

## Remediated example
```hcl
resource "azurerm_monitor_log_profile" "example" {
  name = "default"

  categories = ["Action", "Delete", "Write"]

  locations = ["eastus", "westus"]

  retention_policy {
    enabled = true
    days    = 365
  }
}
```

## Remediation steps
1. Locate the `azurerm_monitor_log_profile` resource (or `Microsoft.Insights/logprofiles` in ARM/Bicep).
2. Set `retention_policy.enabled = true`.
3. Set `retention_policy.days = 365` or greater, or `0` for unlimited retention if your compliance regime allows/requires indefinite retention.
4. Consider also routing the Activity Log to a Log Analytics workspace or immutable storage account (with a separate lifecycle/retention policy) for longer-term, tamper-evident archival beyond what the log profile alone provides.
5. Note: Azure has been deprecating the classic Log Profile API in favor of Diagnostic Settings on the subscription resource — check whether your subscription still uses log profiles or should migrate to `azurerm_monitor_diagnostic_setting` at the subscription scope.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/MonitorLogProfileRetentionDays.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MonitorLogProfileRetentionDays.py)
- [Azure Activity Log overview](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
