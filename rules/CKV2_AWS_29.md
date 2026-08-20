# CKV2_AWS_29: Ensure public API gateway are protected by WAF
## Severity
**HIGH** (score: 7.5/10)

A public API Gateway without WAF protection leaves backend APIs directly exposed to injection, abuse, and automated attack traffic that a WAF would otherwise filter.

## Summary
This check ensures that API Gateway REST APIs (`aws_api_gateway_rest_api`) with a deployed stage are protected by an AWS WAF web ACL, unless the API is a PRIVATE endpoint (not internet-reachable).

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_api_gateway_rest_api`, `aws_api_gateway_stage` (connected `aws_wafv2_web_acl_association` / `aws_wafregional_web_acl_association`)
- **Check type:** Graph-based connection + attribute check

## Why it matters
API Gateway REST APIs are frequently the front door to backend Lambda functions, microservices, or other business logic, and often accept untrusted input directly from the internet. Without WAF in front of them, they are exposed to injection attacks, malformed/oversized payloads, credential stuffing against auth endpoints, and generic bot/scanner abuse — all reaching the backend integration unfiltered. WAF web ACLs let you apply managed rule sets (common vulnerabilities, known bad inputs, IP reputation), rate-based rules to blunt brute-force and DoS attempts, and geo/IP allow-deny lists, all enforced at the edge before invoking backend compute (which is also a cost/DoS control, since unauthenticated Lambda invocations can be a billing attack vector). Skipping WAF on a public API leaves this protection layer entirely absent.

## How Checkov evaluates this
This is a graph check (`APIProtectedByWAF.json`) with an `or` of several scenarios, but they collapse to: the check requires a deployed `aws_api_gateway_stage` to exist for the REST API, and requires a WAF association on that stage **unless** the endpoint type is `PRIVATE`. Specifically:
- If `endpoint_configuration.types` contains `PRIVATE` and a stage exists → PASS (private APIs aren't internet-facing, so WAF isn't required).
- If `endpoint_configuration.types` contains `REGIONAL` and a stage exists and that stage is connected to an `aws_wafregional_web_acl_association` → PASS.
- If `endpoint_configuration.types` contains `REGIONAL` or `EDGE` and a stage exists and that stage is connected to an `aws_wafv2_web_acl_association` → PASS.
- If no `aws_api_gateway_stage` exists at all for the REST API → PASS (an undeployed API has no live public endpoint to protect).

Practically: a `REGIONAL` or `EDGE` (the AWS default) REST API that has a deployed stage but no associated WAFv2 (or, for regional, WAF-classic-regional) web ACL fails this check.

## Non-compliant example
```hcl
resource "aws_api_gateway_rest_api" "public_api" {
  name = "public-api"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_deployment" "public_api_deploy" {
  rest_api_id = aws_api_gateway_rest_api.public_api.id
}

resource "aws_api_gateway_stage" "prod" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.public_api.id
  deployment_id = aws_api_gateway_deployment.public_api_deploy.id
}
# No WAFv2 web ACL association for "prod" stage
```

## Remediated example
```hcl
resource "aws_api_gateway_rest_api" "public_api" {
  name = "public-api"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_deployment" "public_api_deploy" {
  rest_api_id = aws_api_gateway_rest_api.public_api.id
}

resource "aws_api_gateway_stage" "prod" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.public_api.id
  deployment_id = aws_api_gateway_deployment.public_api_deploy.id
}

resource "aws_wafv2_web_acl" "api_waf" {
  name  = "public-api-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "public-api-waf"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
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
}

# The association satisfies the check
resource "aws_wafv2_web_acl_association" "prod_stage_waf" {
  resource_arn = aws_api_gateway_stage.prod.arn
  web_acl_arn  = aws_wafv2_web_acl.api_waf.arn
}
```

## Remediation steps
1. Determine whether the API genuinely needs to be public. If it's meant only for internal/VPC access, set `endpoint_configuration.types = ["PRIVATE"]` with a resource policy restricting it to your VPC endpoints — this both reduces exposure and satisfies the check without WAF.
2. For public (`REGIONAL` or `EDGE`) APIs, create an `aws_wafv2_web_acl` (scope `REGIONAL` for API Gateway) with appropriate managed rule groups and rate-based rules.
3. Add an `aws_wafv2_web_acl_association` (or `aws_wafregional_web_acl_association` for the legacy classic API) referencing the deployed stage's ARN.
4. Repeat for every stage (`dev`, `staging`, `prod`) that is reachable — the check evaluates per-stage connections.
5. Caveat: `EDGE` endpoint type APIs actually sit behind a CloudFront distribution managed by API Gateway; WAFv2 association still applies directly to the API Gateway stage in this model per the check logic, not to a separate CloudFront resource.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/APIProtectedByWAF.json)
- [AWS API Gateway + WAF integration documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html)
