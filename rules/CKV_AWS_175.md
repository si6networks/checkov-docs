# CKV_AWS_175: Ensure WAF has associated rules

## Severity
**LOW** (score: 2.0/10)

A WAF Web ACL with no rules attached provides zero actual filtering despite appearing to be a protective control, leaving the fronted application fully exposed to the layer-7 attacks (SQLi, XSS, bad bots) the WAF was meant to block.

## Summary
This check requires that an AWS WAF Web ACL (classic WAF, WAF Regional, or WAFv2) actually has at least one rule attached, rather than existing as an empty ACL that inspects traffic but blocks/allows nothing meaningfully.

## Applicability
- **Terraform**: `aws_waf_web_acl`, `aws_wafregional_web_acl`, `aws_wafv2_web_acl`

## Why it matters
An empty Web ACL — one with no `rule`/`rules` defined — provides no actual protection despite appearing in the account as a deployed "WAF." Depending on the ACL's default action, it either allows all traffic through unfiltered or blocks everything indiscriminately (rarely the intent), but in either case it fails to provide the differentiated, rule-based inspection (SQLi/XSS pattern matching, rate limiting, geo-blocking, managed rule groups, IP reputation lists) that WAF exists to provide.

This is a common "checkbox compliance" trap: teams attach a WAF to an ALB/CloudFront/API Gateway to satisfy an architecture review or compliance requirement, but if no rules are ever added, the WAF provides a false sense of security while offering zero actual protection against OWASP Top 10 attack patterns, bot traffic, or DDoS-style Layer 7 abuse it's meant to catch.

## How Checkov evaluates this
The check inspects the resource configuration for either a `rules` key (used historically by `aws_waf_web_acl`) or a `rule` key (used by `aws_wafregional_web_acl` and `aws_wafv2_web_acl`). It **PASSES** if either key is present and its value is not simply an empty block placeholder (`!= [{}]`) — i.e., at least one actual rule configuration exists. If neither `rules` nor `rule` is present, or the only value present is an empty `[{}]` placeholder, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_wafv2_web_acl" "main" {
  name        = "app-waf"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "app-waf"
    sampled_requests_enabled   = true
  }
  # No `rule` block defined -> ACL inspects nothing
}
```

## Remediated example
```hcl
resource "aws_wafv2_web_acl" "main" {
  name        = "app-waf"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {  # added
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "commonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "app-waf"
    sampled_requests_enabled   = true
  }
}
```

## Remediation steps
1. Attach at least one `rule` block (WAFv2/WAF Regional) or `rules` entry (classic WAF) to the Web ACL.
2. Start with AWS Managed Rule Groups (e.g. `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesSQLiRuleSet`, `AWSManagedRulesKnownBadInputsRuleSet`) for broad baseline coverage against common web exploits, rather than writing every rule from scratch.
3. Add rate-based rules to mitigate Layer 7 DDoS/brute-force patterns, and IP-set or geo-match rules if you need to allow/deny specific origins.
4. Set rule `priority` values thoughtfully (lower numbers evaluated first) and choose `override_action`/`action` (block, count, allow) deliberately — consider deploying new rules in `count` mode first to validate they don't block legitimate traffic before switching to `block`.
5. Ensure the Web ACL is actually associated with a resource (ALB, CloudFront distribution, API Gateway) via `aws_wafv2_web_acl_association` (or the CloudFront distribution's `web_acl_id`) — this check only validates the ACL has rules, not that it's attached to anything.
6. This is a config-only change deployable without downtime, though newly enforced `block` rules should be validated against real traffic patterns to avoid false-positive outages.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/WAFHasAnyRules.py
- AWS docs: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-groups.html
