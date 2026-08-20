# CKV_AZURE_122: Ensure that Application Gateway uses WAF in "Detection" or "Prevention" modes
## Severity
**LOW** (score: 2.0/10)

A disabled WAF policy means the firewall rules exist but are not actively inspecting or blocking traffic, reducing this to a monitoring/logging gap rather than a fully open attack surface since the WAF component itself may still be provisioned.

## Summary
This check verifies that an Azure Web Application Firewall policy attached to an Application Gateway has its policy settings enabled, so the WAF is actually active (in either Detection or Prevention mode) rather than provisioned but effectively dormant.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_web_application_firewall_policy`

## Why it matters
It's possible to have a WAF policy resource fully defined — with managed rule sets, custom rules, exclusions, etc. — yet have the policy itself administratively disabled, meaning none of that configuration is actually enforced on traffic. This is a subtle but real risk: infrastructure code and dashboards may show "a WAF policy exists," giving a false sense of security, while in fact `policy_settings.enabled` is `false` and every request passes through completely uninspected. This gap between "WAF resource is defined" and "WAF is actually filtering traffic" is exactly the kind of drift that automated policy-as-code checks like this one are designed to catch, since a visual review of Terraform code can easily miss a single `enabled = false`.

## How Checkov evaluates this
This check inspects the `policy_settings` block on `azurerm_web_application_firewall_policy`:
- **FAIL** only if `policy_settings` is present and its `enabled` attribute is explicitly falsey.
- **PASS** in every other case — including when `policy_settings` is absent entirely, or when `enabled` is present and truthy.

Note the pass-by-default behavior: because Azure's own default for `policy_settings.enabled` is `true`, the check treats an absent block as compliant, and only flags an explicit opt-out (`enabled = false`).

## Non-compliant example
```hcl
resource "azurerm_web_application_firewall_policy" "example" {
  name                = "waf-policy-example"
  resource_group_name = azurerm_resource_group.example.name
  location             = "eastus"

  policy_settings {
    enabled = false  # WAF policy exists but is not actually enforced
    mode    = "Prevention"
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
  }
}
```

## Remediated example
```hcl
resource "azurerm_web_application_firewall_policy" "example" {
  name                = "waf-policy-example"
  resource_group_name = azurerm_resource_group.example.name
  location             = "eastus"

  policy_settings {
    enabled = true  # WAF policy is actively enforced
    mode    = "Prevention"
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
  }
}
```

## Remediation steps
1. In the `policy_settings` block, set `enabled = true` (or remove the block if Azure's default is acceptable for your provider version — but explicit is safer).
2. Choose the appropriate `mode`: `"Detection"` for logging-only rollout validation, `"Prevention"` for actual blocking once you've confirmed no false positives.
3. Re-audit any Terraform module or environment where this policy was intentionally disabled (e.g. for a temporary maintenance window) to ensure it was re-enabled afterward.
4. Verify the policy is actually associated with an Application Gateway (`firewall_policy_id`) — an enabled policy that isn't linked to any gateway still provides no protection.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppGWUseWAFMode.py)
- [Azure WAF policy settings documentation](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-configuration)
