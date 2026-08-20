# CKV_AZURE_12: Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'
## Severity
**LOW** (score: 2.0/10)

Short flow log retention limits the ability to investigate and reconstruct network-based incidents after the fact, an audit/forensics gap rather than a direct exploitation vector.

## Summary
This check verifies that Network Watcher NSG Flow Logs are both enabled and configured with a log retention period of at least 90 days (or unlimited retention), ensuring sufficient historical network traffic data is available for investigations.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **IaC frameworks:** Terraform, ARM templates, Bicep (Bicep compiles to ARM, so it's covered by the ARM check)
- **Resource types:**
  - Terraform: `azurerm_network_watcher_flow_log`
  - ARM: `Microsoft.Network/networkWatchers/flowLogs` (and case variants `FlowLogs`, with/without trailing slash)

## Why it matters
NSG Flow Logs record IP traffic flowing through a Network Security Group — source/destination IP, port, protocol, and allow/deny decision. This data is the primary forensic record for investigating a network security incident: without it, once an attacker has been inside the environment for more than a short window, there is no way to reconstruct what hosts they communicated with, what data may have been exfiltrated, or how they moved laterally. A retention period shorter than 90 days is a common finding in incident response: breaches are frequently not detected until weeks or months after initial compromise (industry dwell-time averages are often 60–200+ days), so if logs have already rolled off by the time the incident is discovered, the investigation loses the network evidence entirely. Many compliance frameworks (PCI-DSS in particular) mandate minimum log retention specifically because of this dwell-time problem.

## How Checkov evaluates this
Both implementations require **all** of the following to be true for a PASS:
1. Flow logging is enabled — `properties.enabled` (ARM) or `enabled` (Terraform) is truthy.
2. A retention policy block exists and is itself enabled — `retentionPolicy.enabled` (ARM) or `retention_policy[0].enabled` (Terraform) is truthy.
3. The retention `days` value is either `>= 90`, **or** (Terraform only) exactly `0`, which Azure treats as "retain forever" and therefore also passes.

**FAIL** if flow logging is disabled, if the retention policy is missing/disabled, or if `days` is a nonzero value below 90. The ARM version does not special-case `0` days as passing (it only checks `days >= 90` after confirming retention is enabled), so on ARM a `0` value would need to be traced through carefully — the Terraform check explicitly forgives `0` as "indefinite retention."

## Non-compliant example
```hcl
resource "azurerm_network_watcher_flow_log" "example" {
  network_watcher_name = azurerm_network_watcher.example.name
  resource_group_name   = azurerm_resource_group.example.name
  network_security_group_id = azurerm_network_security_group.example.id
  storage_account_id        = azurerm_storage_account.example.id
  enabled                    = true

  retention_policy {
    enabled = true
    days    = 30  # below the 90-day minimum
  }
}
```

## Remediated example
```hcl
resource "azurerm_network_watcher_flow_log" "example" {
  network_watcher_name = azurerm_network_watcher.example.name
  resource_group_name   = azurerm_resource_group.example.name
  network_security_group_id = azurerm_network_security_group.example.id
  storage_account_id        = azurerm_storage_account.example.id
  enabled                    = true

  retention_policy {
    enabled = true
    days    = 90  # meets the minimum retention requirement
  }
}
```

## Remediation steps
1. Ensure the flow log resource has `enabled = true` at the top level (logging is actually turned on).
2. Add or update the `retention_policy` block with `enabled = true` and `days` set to `90` or greater (or `0` for indefinite retention, on Terraform).
3. For ARM/Bicep templates, set `properties.enabled: true` and `properties.retentionPolicy: { enabled: true, days: 90 }`.
4. Confirm the target storage account has adequate capacity and lifecycle management (e.g. tiering to cool/archive) since longer retention increases storage costs — factor this into your storage account's lifecycle policy.
5. Consider enabling Traffic Analytics on top of the flow logs for easier querying rather than raw log analysis.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NetworkWatcherFlowLogPeriod.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/NetworkWatcherFlowLogPeriod.py)
- [Azure NSG flow logs documentation](https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview)
