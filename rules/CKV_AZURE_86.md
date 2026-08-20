# CKV_AZURE_86: Ensure that Azure Defender is set to On for Container Registries

## Severity
**HIGH** (score: 7.5/10)

Disabled Defender for Container Registries removes vulnerability scanning and threat detection for stored container images, allowing vulnerable or malicious images to go unnoticed rather than creating a direct exposure.

## Summary
This check ensures the Microsoft Defender for Cloud pricing tier for the `ContainerRegistry` resource type is set to `Standard`, enabling Defender scanning for Azure Container Registry.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_security_center_subscription_pricing`

## Why it matters
Container registries are the source of truth for what actually runs in your clusters — if a pushed image contains a vulnerable base layer, an embedded malicious package, or exposed secrets baked into a layer, every deployment pulling that image inherits the risk. Microsoft Defender for Container Registries scans images on push and periodically thereafter for known OS and language-package vulnerabilities, surfacing them before they reach production. Without it enabled, vulnerable or tampered images can be pulled and deployed with no automated pre-deployment vulnerability signal, pushing all detection responsibility onto manual review or runtime security tooling that only sees the problem after the workload is already running.

## How Checkov evaluates this
The check inspects the `azurerm_security_center_subscription_pricing` resource and fails when `resource_type` equals `"ContainerRegistry"` and `tier` is anything other than `"Standard"`. Any other resource type passes regardless of tier, since this check is scoped only to the container registry protection plan.

## Non-compliant example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Free"
  resource_type = "ContainerRegistry"
}
```

## Remediated example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Standard"   # enables Defender for Container Registries
  resource_type = "ContainerRegistry"
}
```

## Remediation steps
1. Set `tier = "Standard"` on the `azurerm_security_center_subscription_pricing` resource with `resource_type = "ContainerRegistry"`.
2. This is a subscription-wide setting — verify with other teams before changing it since it affects all container registries in the subscription.
3. Pair this with a CI/CD gate that blocks deployment of images with unresolved critical/high vulnerabilities found by the scan, so the detection actually prevents deployment rather than just reporting after the fact.
4. Review current Defender for Containers/Registries pricing (often billed per image scan or per registry) before broad rollout. No resource replacement or downtime is required to enable this.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnContainerRegistry.py
- Azure docs: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-container-registries-introduction
