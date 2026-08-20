# CKV2_AWS_33: Ensure AppSync is protected by WAF
## Severity
**LOW** (score: 2.0/10)

An AppSync GraphQL API without WAF protection is exposed to injection, resource-exhaustion (deeply nested query), and abuse attacks that a WAF would normally mitigate at the edge.

## Summary
This check ensures that every AWS AppSync GraphQL API is protected by an associated AWS WAFv2 web ACL.

## Applicability
- **IaC frameworks:** Terraform, CloudFormation
- **Resource types:** `aws_appsync_graphql_api` (Terraform) / `AWS::AppSync::GraphQLApi` (CloudFormation), connected `aws_wafv2_web_acl_association` (Terraform) / `AWS::WAFv2::WebACLAssociation` (CloudFormation)
- **Check type:** Graph-based connection check (both implementations)

## Why it matters
AWS AppSync GraphQL APIs are frequently internet-facing and accept complex, nested query structures from clients. Without a WAF in front of them, they are exposed to GraphQL-specific attack patterns such as deeply nested/recursive queries designed to exhaust backend compute (denial-of-service via query complexity), field-level injection attacks against resolvers backed by databases, batching attacks that bypass rate limits by bundling many operations into a single request, and generic credential-stuffing/bot traffic against authenticated mutations. AWS WAF's managed rule groups (including rules tailored for GraphQL/API abuse) and rate-based rules provide a filtering layer that inspects and can block these requests before they reach AppSync's resolvers and downstream data sources (DynamoDB, Lambda, RDS, etc.), which is important because GraphQL's flexible query language makes it harder for the API layer alone to bound the cost of an arbitrary client request.

## How Checkov evaluates this
Two implementations exist, evaluating the analogous condition for each IaC framework:
- **Terraform** (`AppSyncProtectedByWAF.json`): filters `aws_appsync_graphql_api` resources and requires a graph connection to an `aws_wafv2_web_acl_association` resource.
- **CloudFormation** (`AppSyncProtectedByWAF.json`): filters `AWS::AppSync::GraphQLApi` resources and requires a graph connection to an `AWS::WAFv2::WebACLAssociation` resource.

In both cases, the check simply verifies that a WAFv2 web ACL association resource exists whose target references the AppSync API. No attributes of the API or WAF configuration itself are inspected — the mere presence of the association satisfies the check.

## Non-compliant example
```hcl
resource "aws_appsync_graphql_api" "api" {
  name                = "public-graphql-api"
  authentication_type = "API_KEY"
  schema              = file("schema.graphql")
}
# No aws_wafv2_web_acl_association referencing this API
```

## Remediated example
```hcl
resource "aws_appsync_graphql_api" "api" {
  name                = "public-graphql-api"
  authentication_type = "API_KEY"
  schema              = file("schema.graphql")
}

resource "aws_wafv2_web_acl" "appsync_waf" {
  name  = "appsync-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "appsync-waf"
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
resource "aws_wafv2_web_acl_association" "appsync_assoc" {
  resource_arn = aws_appsync_graphql_api.api.arn
  web_acl_arn  = aws_wafv2_web_acl.appsync_waf.arn
}
```

## Remediation steps
1. Create an `aws_wafv2_web_acl` (Terraform) or `AWS::WAFv2::WebACL` (CloudFormation) with `scope = "REGIONAL"` (AppSync is always regional, not CloudFront-scoped).
2. Include managed rule groups appropriate for GraphQL APIs (e.g., AWS Managed Rules Core rule set, SQL database rule set) and a rate-based rule to blunt query-complexity/DoS abuse.
3. Add an `aws_wafv2_web_acl_association` / `AWS::WAFv2::WebACLAssociation` linking the web ACL's ARN to the AppSync API's ARN.
4. Consider also enabling AppSync's own query depth/complexity limiting features alongside WAF for defense in depth against GraphQL-specific abuse that WAF's generic rules may not fully capture.
5. No resource replacement required — the association is an additive resource; existing API configuration and clients are unaffected.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/AppSyncProtectedByWAF.json)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/graph_checks/AppSyncProtectedByWAF.json)
- [AWS AppSync WAF integration documentation](https://docs.aws.amazon.com/appsync/latest/devguide/WAF-Integration.html)
