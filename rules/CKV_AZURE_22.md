# CKV_AZURE_22: Ensure that 'Send email notification for high severity alerts' is set to 'On'
## Severity
**LOW** (score: 2.0/10)

Disabling email notifications for high-severity Security Center alerts delays administrator awareness of active security findings, degrading incident response time even though the underlying detection and logging still occur.

## Summary
Ensures that Microsoft Defender for Cloud (Security Center) is configured to email account administrators automatically when a high-severity security alert is generated.

## Applicability
- **Terraform**: `azurerm_security_center_contact` — inspects `alerts_to_admins`
- **ARM**: `Microsoft.Security/securityContacts` — inspects `properties.alertsToAdmins` (case-insensitive match against `"on"`)
- **Bicep**: compiles to the ARM resource type above

## Why it matters
Microsoft Defender for Cloud generates high-severity alerts when it detects strong indicators of compromise — active exploitation attempts, malware execution, suspicious lateral movement, exposed credentials being used anomalously, and similar signals that typically warrant immediate human response. If email notification to subscription administrators is disabled, these alerts are only visible to whoever happens to be actively watching the Defender for Cloud dashboard or a connected SIEM/alerting pipeline. In many organizations, no one is continuously monitoring the portal, so a high-severity alert can go unnoticed for hours or days — dramatically increasing dwell time for an active attacker and the potential blast radius of a breach (data exfiltration, lateral movement to other resources, ransomware deployment, etc.). Enabling this setting provides a low-cost, redundant notification channel ensuring the people responsible for the subscription are alerted promptly regardless of whether they are actively monitoring the console.

## How Checkov evaluates this
- **Terraform**: reads the `alerts_to_admins` attribute of `azurerm_security_center_contact`. This is a `BaseResourceValueCheck` (default expected value behavior, effectively requiring a truthy/`true` value) — if not explicitly enabled, the check **FAILS**.
- **ARM**: reads `properties.alertsToAdmins`. The check **PASSES** only if the value, case-insensitively, equals the string `"on"`. Any other value, or a missing `properties`/`alertsToAdmins` key, causes **FAILED**.

## Non-compliant example
```hcl
resource "azurerm_security_center_contact" "example" {
  email = "security-team@contoso.com"
  phone = "+1-555-555-0100"

  alert_notifications = true
  alerts_to_admins    = false   # admins are not emailed on high-severity alerts
}
```

## Remediated example
```hcl
resource "azurerm_security_center_contact" "example" {
  email = "security-team@contoso.com"
  phone = "+1-555-555-0100"

  alert_notifications = true
  alerts_to_admins    = true   # notify subscription admins on high-severity alerts
}
```

## Remediation steps
1. Set `alerts_to_admins = true` on the `azurerm_security_center_contact` resource (or `properties.alertsToAdmins: "On"` in ARM/Bicep).
2. Also confirm `alert_notifications` is enabled and its minimal severity threshold is appropriate (e.g., `alert_notifications { state = "Enabled" minimal_severity = "High" }` on newer provider versions) so notifications actually get sent for the intended alert levels.
3. Ensure the subscription's designated security contact `email`/`phone` fields point to an actively monitored distribution list or on-call rotation, not an individual's personal mailbox.
4. There is only one `azurerm_security_center_contact` resource per subscription in most provider versions — coordinate changes across teams to avoid conflicting configuration drift.
5. Consider pairing this with automated alert forwarding (e.g., to a SIEM via Event Hub/Log Analytics) so email is a backup channel rather than the sole notification path.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SecurityCenterContactEmailAlertAdmins.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterContactEmailAlertAdmins.py
- Azure docs: https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications
