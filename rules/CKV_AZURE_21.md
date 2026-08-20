# CKV_AZURE_21: Ensure that 'Send email notification for high severity alerts' is set to 'On'

## Severity
**LOW** (score: 2.0/10)

Disabling high-severity email alerts delays human awareness of a detected incident but does not itself constitute or enable an exploitable weakness.

## Summary
This check ensures the Azure Security Center (Microsoft Defender for Cloud) security contact is configured to send email notifications when high-severity alerts are triggered.

## Applicability
- **Frameworks:** Terraform, ARM templates, Bicep
- **Resource types:** `azurerm_security_center_contact` (Terraform), `Microsoft.Security/securityContacts` (ARM/Bicep)

## Why it matters
Microsoft Defender for Cloud can detect high-severity security events — active malware, suspicious network activity, compromised credentials, exploitation attempts — often faster than an organization's own monitoring pipeline would. If email alerting for high-severity findings is turned off, these detections may sit unnoticed in the Defender for Cloud portal, only being discovered during a periodic manual review rather than at the moment of detection. This directly increases mean-time-to-detect (MTTD) and mean-time-to-respond (MTTR) for active security incidents — during a live compromise, every hour without visibility into a Defender for Cloud finding is time an attacker can use to escalate privileges, move laterally, or exfiltrate data undetected.

## How Checkov evaluates this
**Terraform** — `BaseResourceValueCheck`:
- **Inspected key:** `alert_notifications`
- No `get_expected_value` override is defined, so it uses the base class's default expected value (`True`). The check effectively PASSES only when `alert_notifications` resolves to a truthy/"on" state and FAILS otherwise.

**ARM/Bicep** — custom `scan_resource_conf`:
- Looks for `conf["properties"]["alertNotifications"]`.
- PASSES only if `properties` exists AND `alertNotifications` exists AND its value, compared case-insensitively as a string, equals `"on"`.
- FAILS if `properties` or `alertNotifications` is missing, or the value is anything other than `"on"` (e.g. `"Off"`).

## Non-compliant example
```hcl
resource "azurerm_security_center_contact" "example" {
  name  = "default"
  email = "security@contoso.com"
  phone = "+1-555-0100"

  alert_notifications = false   # high-severity email alerts disabled
  alerts_to_admins    = true
}
```

## Remediated example
```hcl
resource "azurerm_security_center_contact" "example" {
  name  = "default"
  email = "security@contoso.com"
  phone = "+1-555-0100"

  alert_notifications = true    # high-severity email alerts enabled
  alerts_to_admins    = true
}
```

## Remediation steps
1. Locate the `azurerm_security_center_contact` (Terraform) or `Microsoft.Security/securityContacts` (ARM/Bicep) resource for the subscription.
2. Set `alert_notifications = true` (Terraform), or `properties.alertNotifications = "On"` (ARM/Bicep).
3. Ensure the `email` field points to a monitored distribution list, not an individual's inbox, so alerts are seen even during PTO/staff turnover.
4. Combine with CKV_AZURE_20 (phone contact set) for a complete high-severity notification path.
5. Consider also wiring Defender for Cloud alerts into a SIEM or incident-management tool (e.g. via Azure Monitor action groups / Logic Apps) for teams that need alerting beyond email.

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterContactEmailAlert.py)
- [Checkov ARM check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SecurityCenterContactEmailAlert.py)
- [Azure Defender for Cloud email notifications documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications)
