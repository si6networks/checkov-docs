# CKV_AZURE_85: Ensure that Azure Defender is set to On for Kubernetes

## Severity
**HIGH** (score: 7.5/10)

Disabled Defender for Kubernetes removes threat detection and runtime security alerts for the AKS control plane and workloads, weakening detection of an active compromise without itself being an exploitable hole.

## Summary
This check ensures the Microsoft Defender for Cloud pricing tier for the `KubernetesService` resource type is set to `Standard`, enabling Defender for Kubernetes across the subscription.

## Applicability
- **Terraform**: `azurerm_security_center_subscription_pricing`
- **ARM/Bicep**: `Microsoft.Security/pricings`

## Why it matters
AKS clusters are a high-value target: a compromised container can pivot to the node, escalate to the control plane, or pull cluster secrets if RBAC and network boundaries are weak. Microsoft Defender for Kubernetes (formerly Defender for Containers/Kubernetes) provides cluster-level threat detection — flagging anomalous kubectl/API-server activity, suspicious container image behavior, privileged pod creation, and known attack techniques against Kubernetes control planes — as well as environment hardening recommendations (e.g. CIS benchmark checks). Without it enabled, the platform gives you no dedicated signal that a cluster is being probed or actively exploited beyond generic Azure activity logs, meaning container-level attacks like crypto-mining pod deployment or lateral movement via the API server can go unnoticed.

## How Checkov evaluates this
The check inspects the `azurerm_security_center_subscription_pricing` resource. It fails when `resource_type` (Terraform) or `name` (ARM) equals `"KubernetesService"` and the `tier`/`pricingTier` is anything other than `"Standard"` (case-insensitive in the ARM variant). Any other resource type passes regardless of its tier, since the check is scoped only to the Kubernetes protection plan.

## Non-compliant example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Free"
  resource_type = "KubernetesService"
}
```

## Remediated example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Standard"   # enables Defender for Kubernetes
  resource_type = "KubernetesService"
}
```

## Remediation steps
1. Set `tier = "Standard"` on the `azurerm_security_center_subscription_pricing` resource with `resource_type = "KubernetesService"`.
2. This governs the whole subscription's Kubernetes protection plan, so coordinate with other teams before changing it.
3. Ensure the Defender agent/extension is also deployed to AKS clusters as needed — enabling the plan at the subscription level is one part of full coverage; per-cluster agent deployment may also be required depending on the Defender for Containers architecture in use.
4. Review current per-vCore pricing for Defender for Containers before broad rollout.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnKubernetes.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureDefenderOnKubernetes.py
- Azure docs: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction
