# CKV_AZURE_131: SecureString parameter should not have hardcoded default values / Ensure that 'Security contact emails' is set
## Severity
**LOW** (score: 2.0/10)

A hardcoded default value on a `secureString`/`@secure()` parameter bakes a secret (password, connection string, API key) directly into template source and deployment history, exposing hardcoded/exposed credentials to anyone with repo or activity-log read access.

## Summary
This check ID is used for two distinct purposes depending on framework: for ARM/Bicep templates it flags `secureString`/`@secure()` parameters that carry a hardcoded default value (a likely leaked secret), and for Terraform it separately verifies that an `azurerm_security_center_contact` resource has a security contact email configured.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **ARM templates**: `secureString`-typed template parameters.
- **Bicep**: `string` parameters decorated with `@secure()`.
- **Terraform**: `azurerm_security_center_contact` resource, `email` attribute.

## Why it matters
For the ARM/Bicep variant: a `secureString`/`@secure()` parameter exists specifically to prevent secrets (passwords, connection strings, API keys) from being logged or displayed in deployment history, portal UI, or activity logs. If the template author sets a hardcoded `defaultValue`, that value is baked directly into the template source and any deployment log, completely defeating the purpose of marking the parameter secure — the secret becomes visible to anyone with read access to the template repo or deployment history, and Azure Resource Manager itself documents this as a disallowed test case for secure parameters.

For the Terraform variant: Azure Security Center (Microsoft Defender for Cloud) can email designated contacts when it detects potential security breaches, misconfigurations, or vulnerabilities on subscription resources. Without a configured contact email, critical security alerts may go unnoticed, delaying incident response.

## How Checkov evaluates this
- **ARM** (`SecureStringParameterNoHardcodedValue.py`): For each `secureString` parameter, it reads `conf.get('defaultValue')`. If any truthy value is present, the check FAILS (and records the value for secret-scrubbing); if missing or empty string, it PASSES.
- **Bicep** (`SecureStringParameterNoHardcodedValue.py`): First checks whether the parameter has the `@secure()` decorator; if not, the parameter is a plain string and the result is UNKNOWN (not applicable). If `@secure()` is present, it checks the `default` value the same way as the ARM version — any truthy default FAILS.
- **Terraform** (`SecurityCenterContactEmails.py`, a `BaseResourceValueCheck`): Inspects the `email` attribute on `azurerm_security_center_contact` and expects `ANY_VALUE` (i.e., just needs to be non-empty/set) to PASS.

## Non-compliant example

ARM template with hardcoded secret default:
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "adminPassword": {
      "type": "secureString",
      "defaultValue": "P@ssw0rd1234!"
    }
  },
  "resources": []
}
```

Terraform missing security center contact email:
```hcl
resource "azurerm_security_center_contact" "example" {
  email               = ""
  phone               = "+1-555-555-5555"
  alert_notifications = true
  alerts_to_admins    = true
}
```

## Remediated example

ARM template — remove the hardcoded default (require the value be supplied at deploy time):
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "adminPassword": {
      "type": "secureString"
    }
  },
  "resources": []
}
```

Terraform with contact email configured:
```hcl
resource "azurerm_security_center_contact" "example" {
  email               = "security-alerts@example.com"
  phone               = "+1-555-555-5555"
  alert_notifications = true
  alerts_to_admins    = true
}
```

## Remediation steps
1. For ARM/Bicep `secureString`/`@secure()` parameters, never set `defaultValue`/`default` to a literal secret. Remove the property entirely, or set it to an empty string, and pass the real value via a parameters file, Key Vault reference, or deployment-time input.
2. If you find a template with a hardcoded secret default already committed, treat the secret as compromised: rotate it immediately, then remove it from the template and from git history.
3. For `azurerm_security_center_contact`, always set `email` to a monitored distribution list (not an individual's mailbox) so Defender for Cloud alerts reach the right team.
4. Consider also enabling `alert_notifications` and `alerts_to_admins` so subscription owners/admins are notified as a backstop.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/parameter/SecureStringParameterNoHardcodedValue.py
- Checkov check source (Bicep): https://github.com/bridgecrewio/checkov/blob/main/checkov/bicep/checks/param/azure/SecureStringParameterNoHardcodedValue.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterContactEmails.py
- Microsoft docs: https://docs.microsoft.com/en-us/azure/azure-resource-manager/templates/test-cases#secure-parameters-cant-have-hardcoded-default
