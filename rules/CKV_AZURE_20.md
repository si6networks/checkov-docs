# CKV_AZURE_20: Ensure that security contact 'Phone number' is set

## Severity
**LOW** (score: 2.0/10)

A missing security-contact phone number only delays human escalation during an incident; it does not itself create an exploitable weakness in any resource.

## Summary
This check ensures an Azure Security Center (Microsoft Defender for Cloud) security contact configuration has a non-empty phone number set, so security teams can be reached urgently.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, ARM templates, Bicep
- **Resource types:** `azurerm_security_center_contact` (Terraform), `Microsoft.Security/securityContacts` (ARM/Bicep)

## Why it matters
Microsoft Defender for Cloud notifies designated security contacts when it detects high-severity threats, breaches, or suspicious activity in a subscription. Email-only notification is easy to miss (spam filters, off-hours, inbox overload during an active incident), whereas a phone contact enables Microsoft or an internal escalation process to reach a human quickly during a live security incident, such as a compromised resource actively being exploited. Missing phone contact information delays incident response and increases the effective dwell time of an attacker before human intervention begins — every minute of delay during an active compromise (e.g. crypto-mining malware, data exfiltration, or lateral movement) increases the ultimate blast radius.

## How Checkov evaluates this
**Terraform** — `BaseResourceValueCheck`:
- **Inspected key:** `phone`
- **Expected value:** `ANY_VALUE` (any non-empty value satisfies the check; only an absent or empty phone field fails).

**ARM/Bicep** — custom `scan_resource_conf`:
- Looks for `conf["properties"]["phone"]`.
- PASSES only if `properties` exists AND `properties.phone` exists AND is truthy (non-empty).
- FAILS if `properties` is missing, `phone` is missing, or `phone` is empty/falsy.

## Non-compliant example
```hcl
resource "azurerm_security_center_contact" "example" {
  name  = "default"
  email = "security@contoso.com"
  # phone not set
  alert_notifications = true
  alerts_to_admins    = true
}
```

## Remediated example
```hcl
resource "azurerm_security_center_contact" "example" {
  name  = "default"
  email = "security@contoso.com"
  phone = "+1-555-0100"   # phone number now set

  alert_notifications = true
  alerts_to_admins    = true
}
```

## Remediation steps
1. Locate the `azurerm_security_center_contact` (or `Microsoft.Security/securityContacts` in ARM/Bicep) resource for the subscription.
2. Add a `phone` (Terraform) / `properties.phone` (ARM/Bicep) attribute with a monitored, reachable phone number — ideally a security operations hotline rather than an individual's personal number, to avoid a single point of failure.
3. Verify the number is kept current as team ownership changes; stale contact info defeats the purpose of this control.
4. Combine with CKV_AZURE_21 (email alert notifications) for full high-severity alerting coverage.

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterContactPhone.py)
- [Checkov ARM check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SecurityCenterContactPhone.py)
- [Azure Defender for Cloud security contacts documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications)
