# CKV_AWS_342: Ensure WAF rule has any actions
## Severity
**MEDIUM** (score: 5.5/10)

A WAF rule with no configured action is effectively inert, so malicious requests it is meant to inspect pass through without being blocked or even logged, silently defeating the web application protection layer.

## Summary
Verifies that every rule inside an AWS WAF / WAF Classic / WAF Regional Web ACL or rule group actually specifies an action (or override action, or references a managed rule group), so that matched requests are not silently evaluated with no effect.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework**: Terraform
- **Resource types**: `aws_waf_rule_group`, `aws_waf_web_acl`, `aws_wafregional_rule_group`, `aws_wafregional_web_acl`, `aws_wafv2_rule_group`, `aws_wafv2_web_acl`

## Why it matters
A WAF rule that has no action attached (an empty `action {}` / `override_action {}` block, and no managed rule group statement) does nothing when it matches traffic — it neither blocks, counts, nor allows explicitly, so the traffic simply falls through to the default action or to subsequent rules with no visibility. This is a common misconfiguration: an engineer writes a rule intended to block SQLi or an IP-reputation list but forgets to wire up `block {}` / `allow {}` / `count {}`, resulting in a WAF that appears configured (rules are attached, dashboards show "protected") but is actually not enforcing or even logging the intended control. This creates a false sense of security and can let attacks (SQL injection, XSS, bad-bot traffic, known malicious IPs) pass through undetected while compliance reporting shows a WAF rule "exists."

## How Checkov evaluates this
The check reads the rule list from whichever key is present in the resource config: `rule`, `rules`, or `activated_rule` (each provider/resource type names it differently). For each rule in that list, it is marked `passing` if any of the following is true:
- the rule has an `action` block that is not empty (`!= [{}]`);
- the rule has an `override_action` block that is not empty (`!= [{}]`) — used for rule-group overrides;
- the rule's `statement` block contains a `managed_rule_group_statement` (a reference to an AWS/vendor-managed rule group is considered to define its own actions internally).

If **any** rule in the list fails all three conditions, the whole check **FAILS**. If all rules pass, the check **PASSES**. If no rule list is present at all (or it isn't a list), the result is `UNKNOWN`.

## Non-compliant example
```hcl
resource "aws_wafv2_web_acl" "example" {
  name  = "example-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "block-bad-ips"
    priority = 1

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked.arn
      }
    }

    # No action block defined — this rule has no effect when it matches
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "block-bad-ips"
      sampled_requests_enabled   = true
    }
  }
}
```

## Remediated example
```hcl
resource "aws_wafv2_web_acl" "example" {
  name  = "example-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "block-bad-ips"
    priority = 1

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked.arn
      }
    }

    action {
      block {}   # explicitly block matching requests
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "block-bad-ips"
      sampled_requests_enabled   = true
    }
  }
}
```

## Remediation steps
1. Audit every `rule` / `rules` / `activated_rule` block in your `aws_waf*`, `aws_wafregional_*`, and `aws_wafv2_*` resources.
2. For custom rules built from `statement` blocks (IP sets, regex, SQLi/XSS match statements, rate-based statements), add an explicit `action { block {} }`, `action { allow {} }`, or `action { count {} }` (use `count` only intentionally, for monitoring before enforcing).
3. For rule groups referenced inside a Web ACL (`rule_group_reference_statement` or `activated_rule` referencing a rule group), use `override_action { none {} }` (to keep the rule group's own actions) or `override_action { count {} }` — but ensure it is not left as an empty block.
4. If the rule intentionally wraps a managed rule group (`managed_rule_group_statement`), no additional action is required at this level since the managed group defines its own actions — but you should still verify the group's own `override_action`.
5. Re-run `checkov` to confirm the rule list now reports every rule as having a defined action.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/WAFRuleHasAnyActions.py
- AWS docs: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-action.html
