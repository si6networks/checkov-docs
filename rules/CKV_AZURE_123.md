# CKV_AZURE_123: Ensure that Azure Front Door uses WAF in "Detection" or "Prevention" modes
## Severity
**LOW** (score: 2.0/10)

An inactive WAF policy mode means malicious traffic is not being blocked or flagged even though the firewall infrastructure is in place, weakening web-layer defenses without fully removing them.

## Summary
This check verifies that an Azure Front Door WAF policy is actually enabled/active, so that traffic passing through Front Door is genuinely being inspected rather than having a WAF policy resource defined but administratively turned off.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **IaC frameworks:** Terraform, ARM templates, Bicep
- **Resource types:**
  - Terraform: `azurerm_frontdoor_firewall_policy`
  - ARM: `Microsoft.Network/FrontDoorWebApplicationFirewallPolicies`

## Why it matters
As with Application Gateway WAF policies, a Front Door WAF policy can be fully defined with managed rule sets and custom rules yet be effectively inert if its enable flag is turned off. Since Front Door sits at the network edge for global, internet-facing applications, a silently-disabled WAF policy here means every request — including SQLi, XSS, and known bad-bot traffic — passes straight through to origin with zero inspection, while infrastructure code still visually appears to have "WAF protection configured." This is precisely the kind of discrepancy between intended and actual security posture that manual code review tends to miss and that automated checks are needed to catch.

## How Checkov evaluates this
The Terraform and ARM implementations differ slightly in their default behavior:
- **Terraform** (`azurerm_frontdoor_firewall_policy`): inspects `policy_settings[0].enabled`. **FAIL** only if this attribute is present and explicitly falsey; **PASS** in all other cases (including when the block/attribute is absent, since Azure's default is enabled).
- **ARM** (`Microsoft.Network/FrontDoorWebApplicationFirewallPolicies`): inspects `properties.policySettings.enabledState`. **PASS** only if this value equals the string `"Enabled"`; **FAIL** otherwise, including when the property is missing entirely — the ARM check is stricter/pass-by-explicit-value rather than pass-by-default.

## Non-compliant example
```hcl
resource "azurerm_frontdoor_firewall_policy" "example" {
  name                = "fdwafpolicy"
  resource_group_name = azurerm_resource_group.example.name

  policy_settings {
    enabled = false  # policy exists but is not enforced
    mode    = "Prevention"
  }

  managed_rule {
    type    = "DefaultRuleSet"
    version = "1.0"
  }
}
```

## Remediated example
```hcl
resource "azurerm_frontdoor_firewall_policy" "example" {
  name                = "fdwafpolicy"
  resource_group_name = azurerm_resource_group.example.name

  policy_settings {
    enabled = true  # policy is actively enforced
    mode    = "Prevention"
  }

  managed_rule {
    type    = "DefaultRuleSet"
    version = "1.0"
  }
}
```

## Remediation steps
1. In Terraform, set `policy_settings.enabled = true` on the `azurerm_frontdoor_firewall_policy` resource (or omit the attribute if you're relying on the provider default, though explicit is preferred for auditability).
2. In ARM/Bicep, set `properties.policySettings.enabledState` to the literal string `"Enabled"`.
3. Choose `mode = "Detection"` first to validate no false positives against production traffic, then switch to `"Prevention"`.
4. Confirm the policy is actually linked to the Front Door's frontend endpoint (see CKV_AZURE_121) — an enabled-but-unlinked policy provides no protection.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FrontdoorUseWAFMode.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/FrontdoorUseWAFMode.py)
- [Azure Front Door WAF documentation](https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview)
