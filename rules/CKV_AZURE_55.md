# CKV_AZURE_55: Ensure that Azure Defender is set to On for Servers
## Severity
**LOW** (score: 2.0/10)

Leaving Defender for Servers off removes threat-detection coverage for compute workloads, a common initial-access and post-exploitation target, delaying detection of malware, brute-force, and lateral-movement activity.

## Summary
This check fails when the Azure Security Center (Microsoft Defender for Cloud) pricing tier for the "VirtualMachines" resource type is not set to "Standard", meaning Defender for Servers is not enabled for the subscription.

## Applicability
Applies to Terraform, for the resource type `azurerm_security_center_subscription_pricing`.

## Why it matters
Microsoft Defender for Servers provides threat detection, vulnerability assessment, adaptive application controls, file integrity monitoring, and just-in-time VM access for virtual machines. Without it, VMs in the subscription rely only on baseline Azure security controls and generate no advanced threat alerts — meaning compromises such as malware execution, brute-force RDP/SSH attempts, lateral movement, or fileless attacks can go undetected for extended periods. Given that compute resources are a primary target for attackers (crypto-mining, ransomware, C2 staging), leaving this tier on the "Free" plan means the security team loses visibility into exactly the workloads most likely to be exploited, delaying detection and incident response.

## How Checkov evaluates this
The check inspects the `azurerm_security_center_subscription_pricing` resource's `resource_type` and `tier` attributes. It PASSES if `resource_type` is anything other than `"VirtualMachines"` (i.e., the resource block is for a different Defender plan and this check doesn't apply to it) OR if `resource_type == "VirtualMachines"` and `tier == "Standard"`. It FAILS only when `resource_type == "VirtualMachines"` and `tier` is not `"Standard"` (e.g., `"Free"` or missing).

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
  tier          = "Standard"  # enables Microsoft Defender for Servers
  resource_type = "VirtualMachines"
}
```

## Remediation steps
1. Set `tier = "Standard"` on the `azurerm_security_center_subscription_pricing` resource with `resource_type = "VirtualMachines"`.
2. Be aware Defender for Servers is a paid tier billed per-VM-hour; confirm budget approval before enabling at scale.
3. Consider enabling the Log Analytics agent / Azure Monitor Agent auto-provisioning alongside this so Defender can collect the telemetry it needs.
4. This setting is subscription-wide — one resource block governs the whole subscription's VM protection tier, not per-VM.
5. Review and act on Defender for Cloud recommendations and alerts once enabled; enabling the tier alone doesn't remediate existing misconfigurations.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnServers.py)
- [Azure docs: Microsoft Defender for Servers](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-servers-introduction)
