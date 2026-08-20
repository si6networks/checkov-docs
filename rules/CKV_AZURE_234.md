# CKV_AZURE_234: Ensure that Azure Defender for cloud is set to On for Resource Manager

## Severity
**MEDIUM** (score: 5.0/10)

Disabling Azure Defender (Microsoft Defender for Cloud) for Resource Manager removes threat detection for control-plane API activity, letting malicious or anomalous resource-manager operations go unnoticed.

## Summary
This check ensures that Microsoft Defender for Cloud's protection plan for Azure Resource Manager is enabled (`tier = "Standard"`), which detects suspicious ARM activity such as anomalous deployment and role-assignment patterns.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_security_center_subscription_pricing` resources — inspects the `resource_type` and `tier` attributes, specifically when `resource_type` is `"Arm"`.

## Why it matters
Azure Resource Manager (ARM) is the control-plane API for every resource in a subscription — creating VMs, changing network security group rules, assigning IAM roles, deleting resources, and so on. It is a high-value target: an attacker who compromises a credential with ARM access can pivot to create backdoor identities, disable security controls, exfiltrate data via new storage accounts, or set up persistence (e.g., adding a malicious Azure Automation runbook or a new admin role assignment) — all through legitimate-looking API calls.

Microsoft Defender for Resource Manager analyzes control-plane operations (via Azure Activity Log) using threat intelligence and behavioral analytics to flag anomalies: use of suspicious/deprecated API calls, activity from unusual/anonymized IP ranges (e.g., Tor), privilege escalation via unusual role assignments, and use of credentials/service principals in atypical ways. Without this plan enabled, these control-plane attacks are far less likely to be detected in near-real time, since they often blend in with legitimate administrative activity in raw logs.

## How Checkov evaluates this
`BaseResourceCheck` on `azurerm_security_center_subscription_pricing`. The check specifically targets rows where `resource_type` (case-insensitive) equals `"arm"`. For such a row, it FAILS if `tier` (case-insensitive) is anything other than `"standard"`; it PASSES if `tier == "Standard"`. If `resource_type` is not `"arm"` at all (i.e., this resource configures a different Defender plan, like VMs or Storage), the check trivially PASSES since it's evaluating a different plan.

## Non-compliant example
```hcl
resource "azurerm_security_center_subscription_pricing" "arm" {
  tier          = "Free"
  resource_type = "Arm"   # Defender for Resource Manager left on Free tier -> FAILS
}
```

## Remediated example
```hcl
resource "azurerm_security_center_subscription_pricing" "arm" {
  tier          = "Standard"   # <-- Defender for Resource Manager enabled, PASSES
  resource_type = "Arm"
}
```

## Remediation steps
1. Add (or update) an `azurerm_security_center_subscription_pricing` resource with `resource_type = "Arm"` and `tier = "Standard"`.
2. This setting is subscription-wide — only one such resource per `resource_type` should exist per subscription; verify no conflicting resource sets it back to `"Free"`.
3. Microsoft Defender for Cloud plans incur additional cost per subscription; confirm budget approval before enabling broadly.
4. Route the resulting Defender alerts to your SIEM/SOC workflow (e.g., via Azure Sentinel or Log Analytics) — enabling the plan alone doesn't help unless someone is monitoring the alerts it generates.
5. Repeat this pattern for other Defender plan types (VirtualMachines, StorageAccounts, KeyVaults, etc.) as appropriate for your environment; this specific check only covers the ARM plan.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderDisabledForResManager.py
- Azure docs: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-resource-manager-introduction
