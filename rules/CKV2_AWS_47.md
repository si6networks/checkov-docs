# CKV2_AWS_47: Ensure AWS CloudFront attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability
## Severity
**MEDIUM** (score: 5.0/10)

Missing the AWS-managed WAF rule groups that detect Log4j exploitation patterns removes a key compensating control against the Log4Shell RCE vector for applications served through CloudFront.

## Summary
This check fails when a CloudFront distribution is associated with a WAFv2 WebACL, but that WebACL's rules do not include the AWS Managed Rule groups `AWSManagedRulesAnonymousIpList` and `AWSManagedRulesKnownBadInputsRuleSet`, which together provide protection against known Log4Shell (Log4j, CVE-2021-44228) style exploitation traffic and requests from anonymizing sources.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_cloudfront_distribution`, `aws_wafv2_web_acl`

## Why it matters
Log4Shell (CVE-2021-44228) was a critical, wormable, unauthenticated remote code execution vulnerability in the widely-used Log4j Java logging library, exploited by embedding a malicious JNDI lookup string (`${jndi:ldap://...}`) in virtually any request field that gets logged — headers, User-Agent, query parameters, even fields as obscure as passwords or file names. Because the payload can arrive through so many vectors, exploitation attempts are often filtered at the WAF layer rather than the application layer. AWS's `AWSManagedRulesKnownBadInputsRuleSet` includes rules (e.g. `Log4JRCE`) specifically written to detect and block these JNDI/LDAP-lookup patterns before they ever reach the application. `AWSManagedRulesAnonymousIpList` blocks traffic from VPNs, proxies, Tor exit nodes and hosting providers commonly used to mask the source of exploitation and scanning traffic. A CloudFront distribution with a WAF attached but missing these rule groups gives a false sense of protection — the WAF is present, but not actually defending against this specific, high-impact class of attack.

## How Checkov evaluates this
This is a graph-based JSON policy requiring all of the following (`and`):
1. The resource under evaluation is an `aws_cloudfront_distribution` (via `resource_type` filter).
2. It has a graph connection to an `aws_wafv2_web_acl` (i.e., `web_acl_id` references a WebACL).
3. That WebACL's `rule.*.statement.managed_rule_group_statement.name` list contains `AWSManagedRulesAnonymousIpList`.
4. That same rule-name list also contains `AWSManagedRulesKnownBadInputsRuleSet`.
- **FAIL** if the distribution has no attached WebACL at all, or the attached WebACL is missing either managed rule group by name.
- **PASS** only when both named managed rule groups are present among the WebACL's rules (their `action`/override status and rule priority are not evaluated by this specific check — only presence in the rule list).

## Non-compliant example
```hcl
resource "aws_wafv2_web_acl" "bad" {
  name        = "cloudfront-waf"
  scope       = "CLOUDFRONT"
  provider    = aws.us_east_1

  default_action {
    allow {}
  }

  rule {
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
      metric_name                = "common-rule-set"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "cloudfront-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudfront_distribution" "bad" {
  enabled  = true
  web_acl_id = aws_wafv2_web_acl.bad.arn
  # ... origin, default_cache_behavior, restrictions, viewer_certificate omitted for brevity
}
```

## Remediated example
```hcl
resource "aws_wafv2_web_acl" "good" {
  name     = "cloudfront-waf"
  scope    = "CLOUDFRONT"
  provider = aws.us_east_1

  default_action {
    allow {}
  }

  rule {
    name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet" # blocks Log4Shell/JNDI payloads
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
    name     = "AWS-AWSManagedRulesAnonymousIpList"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList" # blocks anonymizing proxies/VPNs/Tor
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
    metric_name                = "cloudfront-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudfront_distribution" "good" {
  enabled    = true
  web_acl_id = aws_wafv2_web_acl.good.arn
  # ... origin, default_cache_behavior, restrictions, viewer_certificate omitted for brevity
}
```

## Remediation steps
1. Attach a `aws_wafv2_web_acl` (scope `CLOUDFRONT`, created in `us-east-1`) to the CloudFront distribution's `web_acl_id`.
2. Add a `rule` block with a `managed_rule_group_statement` referencing vendor name `AWS` and rule group name `AWSManagedRulesKnownBadInputsRuleSet`.
3. Add another `rule` block for `AWSManagedRulesAnonymousIpList`.
4. Set `override_action { none {} }` initially so the rule group's own block/count actions apply as designed; move to `count` only temporarily while testing for false positives, then revert to `none`.
5. Include a `visibility_config` block on every rule and on the WebACL itself (required by the provider).
6. Consider also adding `AWSManagedRulesCommonRuleSet` and `AWSManagedRulesSQLiRuleSet` for broader coverage — this specific check only verifies the two Log4j-relevant groups.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/CloudFrontWebACLConfiguredWIthLog4jVulnerability.json
- AWS docs: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
