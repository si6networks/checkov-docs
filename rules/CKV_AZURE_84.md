# CKV_AZURE_84: Ensure that Azure Defender is set to On for Storage

## Severity
**LOW** (score: 2.0/10)

Disabled Defender for Storage removes automated detection of anomalous access, malware uploads, and data exfiltration against storage accounts, delaying response to a compromise rather than causing one.

## Summary
This check ensures the Microsoft Defender for Cloud pricing tier for the `StorageAccounts` resource type is set to `Standard`, enabling Defender for Storage across the subscription.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_security_center_subscription_pricing`
- **ARM/Bicep**: `Microsoft.Security/pricings`

## Why it matters
Storage accounts are a common target for both external attackers (exposed blob containers, leaked SAS tokens/access keys) and malicious insiders uploading harmful content. Microsoft Defender for Storage adds threat detection for anomalous access patterns (e.g. access from Tor exit nodes, unusual anonymous access spikes, unexpected access-key/SAS usage patterns) and malware scanning on uploaded blobs. Without it enabled, a compromised access key or an inadvertently public container can be actively exploited — for example to distribute malware or exfiltrate data — with no automated alerting, relying entirely on manual detection or downstream damage to surface the issue.

## How Checkov evaluates this
The check inspects the `azurerm_security_center_subscription_pricing` resource. It fails when `resource_type` equals `"StorageAccounts"` (Terraform) — or `properties.pricingTier` combined with the resource simply being of this type in ARM — and the `tier` is anything other than `"Standard"`. Any other `resource_type` value passes regardless of tier, since this check is scoped specifically to the storage protection plan.

## Non-compliant example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Free"
  resource_type = "StorageAccounts"
}
```

## Remediated example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Standard"   # enables Defender for Storage
  resource_type = "StorageAccounts"
}
```

## Remediation steps
1. Set `tier = "Standard"` on the `azurerm_security_center_subscription_pricing` resource with `resource_type = "StorageAccounts"`.
2. This is a subscription-wide setting — confirm with other teams before changing it, since one resource typically governs the whole subscription's Storage protection plan.
3. Review Defender for Storage's current pricing model (per-transaction or per-storage-account, depending on plan version) before enabling broadly, to anticipate cost impact.
4. No resource replacement or downtime is required.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnStorage.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureDefenderOnStorage.py
- Azure docs: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction
