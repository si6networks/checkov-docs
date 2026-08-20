# CKV2_AWS_78: Ensure AWS AppSync attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability

## Severity
**HIGH** (score: 7.8/10)

An AppSync GraphQL API without a WAF ACL enforcing anonymous-IP and known-bad-input rules is exposed to Log4Shell-style remote code execution attempts.

## Summary
This check ensures that an AWS AppSync GraphQL API has an AWS WAFv2 Web ACL attached, and that the Web ACL includes the AWS Managed Rule groups that mitigate Log4Shell (Log4j, CVE-2021-44228) style injection attacks.

## Applicability
- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `aws_appsync_graphql_api` and `aws_wafv2_web_acl` (via `aws_wafv2_web_acl_association`).

## Why it matters
AppSync GraphQL APIs accept arbitrary, deeply nested query/variable payloads from clients, which are commonly logged (query text, variables, headers) by resolvers, Lambda data sources, or observability tooling. If any component in that chain uses a vulnerable Log4j 2.x version, an attacker can embed a JNDI lookup string (`${jndi:ldap://...}`) inside a GraphQL variable or header and trigger remote code execution or credential exfiltration the moment it's logged. Because GraphQL APIs are also frequently public-facing and accept flexible, attacker-controlled string content across many fields, they are a broad injection surface for this specific class of attack. `AWSManagedRulesKnownBadInputsRuleSet` includes purpose-built signatures for Log4Shell payloads, and `AWSManagedRulesAnonymousIpList` blocks traffic originating from anonymizing proxies commonly used for mass scanning of this vulnerability.

## How Checkov evaluates this
Graph check (`AppsyncWebACLConfiguredWIthLog4jVulnerability.json`). It flags an `aws_appsync_graphql_api` as **failing** if either:
1. It has **no** connected `aws_wafv2_web_acl_association`, **or**
2. It has an association whose linked `aws_wafv2_web_acl` exists but whose rules do **not** include both a managed rule group statement named `AWSManagedRulesAnonymousIpList` and one named `AWSManagedRulesKnownBadInputsRuleSet`.

PASS requires a WAFv2 Web ACL attached with both of those managed rule groups present.

## Non-compliant example
```hcl
resource "aws_appsync_graphql_api" "api" {
  name                = "public-graphql-api"
  authentication_type = "API_KEY"
  schema              = file("schema.graphql")
}
# No aws_wafv2_web_acl_association -> fails
```

## Remediated example
```hcl
resource "aws_appsync_graphql_api" "api" {
  name                = "public-graphql-api"
  authentication_type = "API_KEY"
  schema              = file("schema.graphql")
}

resource "aws_wafv2_web_acl" "appsync_protection" {
  name  = "appsync-log4j-protection"
  scope = "REGIONAL"

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
    metric_name                = "appsync-log4j-protection"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "appsync" {
  resource_arn = aws_appsync_graphql_api.api.arn
  web_acl_arn  = aws_wafv2_web_acl.appsync_protection.arn
}
```

## Remediation steps
1. Attach a WAFv2 Web ACL to the AppSync API via `aws_wafv2_web_acl_association` pointing to the API's ARN.
2. Ensure the Web ACL includes both `AWSManagedRulesKnownBadInputsRuleSet` and `AWSManagedRulesAnonymousIpList`.
3. Use `scope = "REGIONAL"` for AppSync (it is a regional API, not distributed via CloudFront directly).
4. Test in WAF "count" mode first to confirm legitimate GraphQL queries (which can contain complex nested JSON) aren't falsely blocked, then switch to blocking mode.
5. Treat this as defense-in-depth, not a substitute for patching Log4j versions in any Lambda resolvers/data sources behind the API to >= 2.17.1.
6. Consider adding rate-based rules alongside the managed groups if the API is public, to blunt scanning traffic further.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/AppsyncWebACLConfiguredWIthLog4jVulnerability.json)
- [AWS: Baseline Rule Groups for AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html)
