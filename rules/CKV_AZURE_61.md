# CKV_AZURE_61: Ensure that Azure Defender is set to On for App Service
## Severity
**LOW** (score: 2.0/10)

Without Defender for App Service, compromise of an internet-facing web or function app (a common initial-access vector) generates no dedicated alert for post-exploitation behavior like webshells or C2 traffic, extending attacker dwell time.

## Summary
This check fails when the Azure Security Center (Microsoft Defender for Cloud) pricing tier for the "AppServices" resource type is not set to "Standard", meaning Defender for App Service is not enabled for the subscription.

## Applicability
Applies to Terraform, for the resource type `azurerm_security_center_subscription_pricing`.

## Why it matters
Microsoft Defender for App Service analyzes App Service instances (web apps, API apps, Function Apps) for suspicious activity such as unusual outbound network calls, execution of suspicious commands, potential exploitation attempts (e.g. against known web app vulnerabilities), and access from anomalous locations. App Service workloads are frequently internet-facing and are a common initial-access vector for attackers exploiting web application vulnerabilities (SSRF, RCE via deserialization, path traversal, etc.). Without Defender for App Service enabled, an attacker who compromises a web app can operate largely undetected — there's no dedicated threat-detection layer flagging the post-exploitation behavior (webshell activity, outbound C2 connections, cryptomining processes) that this plan is specifically built to catch.

## How Checkov evaluates this
The check inspects the `azurerm_security_center_subscription_pricing` resource's `resource_type` and `tier` attributes. It PASSES if `resource_type` is anything other than `"AppServices"` (a different Defender plan, not the target of this check) OR if `resource_type == "AppServices"` and `tier == "Standard"`. It FAILS only when `resource_type == "AppServices"` and `tier` is not `"Standard"` (e.g. `"Free"` or unset).

## Non-compliant example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Free"
  resource_type = "AppServices"
}
```

## Remediated example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Standard"  # enables Microsoft Defender for App Service
  resource_type = "AppServices"
}
```

## Remediation steps
1. Set `tier = "Standard"` on the `azurerm_security_center_subscription_pricing` resource with `resource_type = "AppServices"`.
2. This setting applies subscription-wide, protecting all App Service plans/instances in the subscription — no per-app configuration is needed.
3. Confirm cost implications: Defender for App Service is billed per App Service Plan instance, not per app.
4. After enabling, review Defender for Cloud's recommendations for App Service (e.g. enabling diagnostic logging, disabling remote debugging, enforcing HTTPS) as complementary hardening, since Defender's detections work best alongside good baseline configuration.
5. Ensure alerts routing (e.g. to a SIEM or Microsoft Sentinel) is configured so App Service alerts are actually triaged, not just generated.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnAppServices.py)
- [Azure docs: Microsoft Defender for App Service](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction)
