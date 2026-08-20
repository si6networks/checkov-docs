# CKV2_AWS_77: Ensure AWS API Gateway Rest API attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability

## Severity
**HIGH** (score: 7.8/10)

A public API Gateway without WAF protection against known bad inputs/anonymous IPs remains open to Log4Shell-class remote code execution attempts against backend services.

## Summary
This check ensures that API Gateway stages/APIs have an AWS WAFv2 Web ACL attached, and that the Web ACL includes the AWS Managed Rule groups that mitigate Log4Shell (Log4j, CVE-2021-44228) style injection attacks.

## Applicability
- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `aws_api_gateway_stage` (REST APIs), `aws_apigatewayv2_api` (HTTP/WebSocket APIs), and `aws_wafv2_web_acl` (via `aws_wafv2_web_acl_association`).

## Why it matters
API Gateway is frequently the front door for backend services (often Lambda functions) that may include vulnerable logging libraries. Log4Shell payloads are commonly smuggled through request headers, query strings, or JSON bodies that API Gateway simply forwards along. Without a WAF, or with a WAF missing the relevant managed rule groups, malicious JNDI lookup strings pass straight through to backend compute where a vulnerable Log4j version could trigger remote code execution or exfiltrate environment secrets via outbound LDAP/RMI callbacks. `AWSManagedRulesKnownBadInputsRuleSet` contains signatures for this exploitation pattern, and `AWSManagedRulesAnonymousIpList` blocks traffic from anonymizing infrastructure often used in mass internet scanning for this exact vulnerability.

## How Checkov evaluates this
Graph check (`APIGatewayWebACLConfiguredWIthLog4jVulnerability.json`). It flags a resource (`aws_apigatewayv2_api` or `aws_api_gateway_stage`) as **failing** if either:
1. It has **no** connected `aws_wafv2_web_acl_association` at all, **or**
2. It has a connected association, and the linked `aws_wafv2_web_acl` exists, but its rules do **not** include both a managed rule group statement named `AWSManagedRulesAnonymousIpList` and one named `AWSManagedRulesKnownBadInputsRuleSet`.

PASS requires a WAFv2 Web ACL to be attached that contains both of those managed rule groups.

## Non-compliant example
```hcl
resource "aws_apigatewayv2_api" "http_api" {
  name          = "public-http-api"
  protocol_type = "HTTP"
}
# No aws_wafv2_web_acl_association -> fails
```

## Remediated example
```hcl
resource "aws_apigatewayv2_api" "http_api" {
  name          = "public-http-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http_api.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_wafv2_web_acl" "api_protection" {
  name  = "api-log4j-protection"
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
    metric_name                = "api-log4j-protection"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "api_stage" {
  resource_arn = aws_apigatewayv2_stage.default.arn
  web_acl_arn  = aws_wafv2_web_acl.api_protection.arn
}
```

## Remediation steps
1. Attach a WAFv2 Web ACL to every REST API stage or HTTP API via `aws_wafv2_web_acl_association`.
2. Ensure the Web ACL includes `AWSManagedRulesKnownBadInputsRuleSet` and `AWSManagedRulesAnonymousIpList`.
3. Note: WAFv2 can only be associated with API Gateway REST API **stages**, not the REST API resource directly — associate at the stage level (`aws_api_gateway_stage`); for HTTP APIs, association is against `aws_apigatewayv2_stage`'s ARN even though the graph check filters on `aws_apigatewayv2_api`/`aws_api_gateway_stage`.
4. Use `scope = "REGIONAL"` (API Gateway is a regional service, not CloudFront).
5. Validate WAF doesn't introduce false positives for legitimate payloads (e.g. JSON bodies containing benign `${...}`-like strings) — test in count mode before enforcing block mode broadly.
6. This is a compensating control; also ensure Log4j dependencies in backend Lambda/EC2/ECS workloads are patched to a fixed version (>= 2.17.1).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/APIGatewayWebACLConfiguredWIthLog4jVulnerability.json)
- [AWS: Baseline Rule Groups for AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html)
