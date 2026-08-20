# CKV_AZURE_135: Ensure Application Gateway WAF prevents message lookup in Log4j2 (CVE-2021-44228, "Log4Shell")
## Severity
**LOW** (score: 2.0/10)

Like its Front Door counterpart, this check verifies the Application Gateway WAF blocks the Log4Shell (CVE-2021-44228) pattern, so a failure leaves internet-facing web applications open to remote code execution via a well-known exploit.

## Summary
This check ensures an Azure Application Gateway WAF policy uses the OWASP managed rule set (version 3.1 or 3.2) with the Log4Shell-detecting rule (`944240`, in rule group `REQUEST-944-APPLICATION-ATTACK-JAVA`) not disabled.

## Applicability
- **ARM**: `Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies` resources.
- **Terraform**: `azurerm_web_application_firewall_policy` resource.
- **Bicep**: compiles to the same ARM resource type.

## Why it matters
CVE-2021-44228 (Log4Shell) is a critical RCE in Apache Log4j2, triggered when an attacker-controlled string containing a JNDI lookup pattern (`${jndi:...}`) reaches a vulnerable logging call. Because Application Gateway commonly fronts Java-based web applications and APIs, and Log4j2 is deeply embedded across the Java ecosystem (often several dependency layers deep, making full inventory and patching slow), the WAF's OWASP Core Rule Set Java attack detections (rule `944240`) act as a critical compensating control that blocks exploit payloads at the network edge before they reach potentially-unpatched backend application code. If this rule group is missing from the managed rule set, uses an older/unsupported CRS version, or the specific rule is explicitly disabled in a `rule_group_override`, Log4Shell exploitation attempts pass straight through to backend pools.

## How Checkov evaluates this
The check inspects `managed_rules[0].managed_rule_set` entries, filtering to those where `type` is `OWASP` (or unset, since OWASP is default) and `version` is `3.1` or `3.2` (older CRS versions that lack this coverage, or missing entirely, fail). For a matching rule set:
- It looks at `rule_group_override` entries for `rule_group_name == "REQUEST-944-APPLICATION-ATTACK-JAVA"`.
- If found, and its `disabled_rules` list contains `"944240"`, the check FAILS (rule explicitly disabled).
- Otherwise (rule group not overridden, or overridden without disabling `944240`), it PASSES.
- If `managed_rules` is absent entirely, or no OWASP 3.1/3.2 rule set is found, the result is FAILED (fail-closed default).

## Non-compliant example
```hcl
resource "azurerm_web_application_firewall_policy" "example" {
  name                = "example-waf-policy"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"

      rule_group_override {
        rule_group_name = "REQUEST-944-APPLICATION-ATTACK-JAVA"
        disabled_rules   = ["944240"]  # Log4Shell detection disabled -- FAILS
      }
    }
  }

  policy_settings {
    enabled = true
    mode    = "Prevention"
  }
}
```

## Remediated example
```hcl
resource "azurerm_web_application_firewall_policy" "example" {
  name                = "example-waf-policy"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
      # no override disabling rule 944240 -- Log4Shell detection remains active
    }
  }

  policy_settings {
    enabled = true
    mode    = "Prevention"
  }
}
```

## Remediation steps
1. Use OWASP CRS version `3.1` or `3.2` (or later, if supported by your Checkov version) rather than older/legacy rule sets.
2. Do not add a `rule_group_override` for `REQUEST-944-APPLICATION-ATTACK-JAVA` that disables rule `944240`. If you must override the group for other rules, leave `944240` out of `disabled_rules`.
3. Confirm `policy_settings.mode` is `Prevention`, not `Detection`, so matched requests are actually blocked, not just logged.
4. Continue patching Log4j2 to a fixed version (>= 2.17.1) in application dependencies — the WAF rule is a compensating control, not a substitute for remediating the library.
5. After changes, run WAF logs/test traffic with a benign JNDI-pattern test string to confirm the rule is actively blocking as expected.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppGatewayWAFACLCVE202144228.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppGatewayWAFACLCVE202144228.py
- CVE record: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Microsoft docs on Application Gateway WAF CRS: https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules
