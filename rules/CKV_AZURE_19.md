# CKV_AZURE_19: Ensure that standard pricing tier is selected

## Severity
**LOW** (score: 2.0/10)

Using the free Security Center tier instead of Standard disables key Microsoft Defender for Cloud threat-detection and vulnerability-assessment capabilities, leaving the subscription without timely alerting on active attacks or exposed misconfigurations.

## Summary
This check ensures Azure Security Center (Microsoft Defender for Cloud) pricing for a resource category is set to the `Standard` tier rather than `Free`, so advanced threat protection features are active.

## Applicability
- **Frameworks:** Terraform (`azurerm` provider), ARM templates, Bicep (compiled to ARM)
- **Resource types:**
  - ARM: `Microsoft.Security/pricings`
  - Terraform: `azurerm_security_center_subscription_pricing`

## Why it matters
Azure Security Center / Microsoft Defender for Cloud's `Free` tier provides only basic security recommendations and a secure score, with no active threat detection. The `Standard` (paid) tier enables Microsoft Defender plans for the resource type in question (e.g. servers, storage, SQL, Key Vault, containers) — including behavioral analytics, anomaly detection, just-in-time VM access, file integrity monitoring, and alerting on suspicious activity such as brute-force attempts, unusual data exfiltration patterns, or known malware signatures. Leaving pricing on `Free` means an organization has visibility into misconfigurations but no real-time detection of active attacks or compromise — a significant blind spot for incident detection and response, particularly for resource types handling sensitive data (SQL, Storage, Key Vault).

## How Checkov evaluates this
**ARM:** Reads `properties.pricingTier` from the `Microsoft.Security/pricings` resource. If it equals `"standard"` (case-insensitive), the check PASSES; otherwise (including if the field is missing) it FAILS.

**Terraform:** Reads the `tier` attribute of `azurerm_security_center_subscription_pricing` and compares it against the expected value `"Standard"`. Any other value (typically `"Free"`) FAILS.

## Non-compliant example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Free"
  resource_type = "VirtualMachines"
}
```

## Remediated example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}
```

## Remediation steps
1. Set `tier = "Standard"` for every `azurerm_security_center_subscription_pricing` resource covering the resource types relevant to your workloads (e.g. `VirtualMachines`, `SqlServers`, `AppServices`, `StorageAccounts`, `KeyVaults`, `containers`, etc.).
2. Repeat for each `resource_type` category individually — pricing tier is set per resource type, not globally, so a single resource covering `VirtualMachines` does not protect `StorageAccounts`.
3. Budget for the added cost of Microsoft Defender plans — Standard tier pricing is per-resource/per-month and varies by plan.
4. Review the specific Microsoft Defender plan features enabled for each resource type (e.g. Defender for Storage's malware scanning, Defender for SQL's vulnerability assessment) to ensure the relevant sub-features are also turned on where configurable.
5. This is a subscription-level (or management-group-level) setting; changes typically apply immediately with no downtime to the protected resources.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SecurityCenterStandardPricing.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterStandardPricing.py
- [Microsoft Defender for Cloud pricing documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/plan-defender-for-cloud-microsoft-cloud-security-benchmark)
