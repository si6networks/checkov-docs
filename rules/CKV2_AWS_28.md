# CKV2_AWS_28: Ensure public facing ALB are protected by WAF
## Severity
**HIGH** (score: 7.5/10)

An internet-facing load balancer without WAF protection is fully exposed to common web application attacks (SQLi, XSS, bad bots, layer-7 DDoS) with no compensating control in front of it.

## Summary
This check ensures that internet-facing Application Load Balancers (`aws_lb`/`aws_alb` of type `application`) have an AWS WAF web ACL associated with them, either via WAFv2 or the legacy WAF Regional association.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_lb`, `aws_alb` (and their connected `aws_wafv2_web_acl_association` / `aws_wafregional_web_acl_association`)
- **Check type:** Graph-based connection + attribute check

## Why it matters
An application load balancer that is internet-facing and has no WAF in front of it exposes the backend application directly to layer-7 attacks: SQL injection, cross-site scripting, remote file inclusion, credential-stuffing/brute-force login attempts, and known bad-bot/scanner traffic. WAF provides a centrally managed, pattern/rule-based filtering layer (AWS Managed Rules, rate-based rules, geo-blocking, IP reputation lists) that can block or challenge malicious requests before they ever reach application code — protecting against vulnerability classes even when the application itself has not yet been patched. Without it, every request reaches the origin, and the app's own code is the sole line of defense against exploitation attempts, which is a much weaker security posture for any publicly reachable HTTP(S) endpoint.

## How Checkov evaluates this
This is a graph check (`ALBProtectedByWAF.json`). It filters resources of type `aws_lb`/`aws_alb`, and passes if **any** of these conditions hold:
- A graph connection exists between the load balancer and an `aws_wafv2_web_acl_association` resource, OR
- A graph connection exists between the load balancer and an `aws_wafregional_web_acl_association` resource, OR
- The load balancer's `internal` attribute equals `true` (i.e., it's not internet-facing, so WAF protection is considered non-critical), OR
- The load balancer's `load_balancer_type` is `network` or `gateway` (WAF doesn't apply to NLBs/Gateway LBs — those operate at layer 3/4, not layer 7).

The check therefore only fails for an internet-facing (`internal = false` or unset) Application Load Balancer (`load_balancer_type = "application"` or unset, which defaults to `application`) that has no WAF web ACL association anywhere in the configuration.

## Non-compliant example
```hcl
resource "aws_lb" "public_app" {
  name               = "public-app-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.alb_sg.id]
}
# No aws_wafv2_web_acl_association referencing this ALB
```

## Remediated example
```hcl
resource "aws_lb" "public_app" {
  name               = "public-app-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.alb_sg.id]
}

resource "aws_wafv2_web_acl" "public_app_waf" {
  name  = "public-app-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "public-app-waf"
    sampled_requests_enabled   = true
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
}

# The association satisfies the check
resource "aws_wafv2_web_acl_association" "public_app_waf_assoc" {
  resource_arn = aws_lb.public_app.arn
  web_acl_arn  = aws_wafv2_web_acl.public_app_waf.arn
}
```

## Remediation steps
1. Identify every `aws_lb`/`aws_alb` with `internal = false` (or unset) and `load_balancer_type = "application"` (or unset).
2. Create an `aws_wafv2_web_acl` with appropriate managed/custom rule groups (start with AWS Managed Rules Common Rule Set and known-bad-inputs rule group).
3. Add an `aws_wafv2_web_acl_association` linking the web ACL to the ALB's ARN.
4. If your ALB is regional and you're on the legacy WAF Classic Regional API, use `aws_wafregional_web_acl_association` instead.
5. If the ALB is genuinely intended to be internal-only, explicitly set `internal = true` — this both documents intent and satisfies the check without requiring WAF.
6. Caveat: WAF web ACLs incur per-request and per-rule evaluation costs; review AWS WAF pricing before attaching broad managed rule groups to high-traffic ALBs.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/ALBProtectedByWAF.json)
- [AWS WAF documentation](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)
