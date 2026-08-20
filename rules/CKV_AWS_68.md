# CKV_AWS_68: CloudFront Distribution should have WAF enabled
## Severity
**LOW** (score: 2.0/10)

Without a WAF in front of a CloudFront distribution, the application loses a layer of defense against common web exploits (SQLi, XSS, layer-7 DDoS), increasing exposure to attacks that a properly configured origin might otherwise mitigate.

## Summary
This check verifies that a CloudFront distribution has a Web Application Firewall (WAF) Web ACL attached (a non-empty `WebACLId`/`web_acl_id`), providing a layer of protection against common web exploits before requests reach the origin.

## Applicability
- **CloudFormation**: `AWS::CloudFront::Distribution`, property `Properties/DistributionConfig/WebACLId`.
- **Terraform**: `aws_cloudfront_distribution` resource, attribute `web_acl_id`.

## Why it matters
CloudFront distributions are frequently the public-facing edge for web applications and APIs, making them a prime target for injection attacks (SQLi, XSS), bot traffic, credential stuffing, and volumetric/application-layer DDoS attempts. Without AWS WAF attached, none of that traffic is inspected or filtered at the edge — malicious requests pass straight through to the origin (an ALB, S3 static site, or custom origin), relying entirely on the origin application's own defenses, if any. WAF lets you apply managed rule groups (AWS Managed Rules for OWASP Top 10, SQLi, known bad inputs), rate-based rules to blunt credential-stuffing/DDoS attempts, and geo/IP-based blocking — all evaluated at the CloudFront edge, closer to the attacker and before consuming origin compute/bandwidth. Omitting WAF means losing this first line of defense and pushing all attack-mitigation burden onto the application layer.

## How Checkov evaluates this
Both are `BaseResourceValueCheck` implementations using `ANY_VALUE` as the expected value:
- **CloudFormation**: inspects `Properties/DistributionConfig/WebACLId`.
- **Terraform**: inspects `web_acl_id`.
- PASS: the attribute is present and set to any non-empty value (i.e., a Web ACL ARN/ID is attached).
- FAIL: the attribute is absent, or explicitly set to an empty string (CloudFront's own default when no WAF is associated).

Checkov does not validate what rules the referenced Web ACL contains — only that some Web ACL is associated with the distribution.

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "site" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id    = "s3-origin"
  }

  default_cache_behavior {
    target_origin_id       = "s3-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods          = ["GET", "HEAD"]
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
  # no web_acl_id -> non-compliant
}
```

## Remediated example
```hcl
resource "aws_wafv2_web_acl" "site" {
  name        = "site-protection"
  scope       = "CLOUDFRONT"
  provider    = aws.us_east_1   # WAFv2 for CloudFront must be created in us-east-1

  default_action {
    allow {}
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
      metric_name                = "commonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "siteWebAcl"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudfront_distribution" "site" {
  enabled  = true
  web_acl_id = aws_wafv2_web_acl.site.arn   # fixed

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id    = "s3-origin"
  }

  default_cache_behavior {
    target_origin_id       = "s3-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods          = ["GET", "HEAD"]
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
```

## Remediation steps
1. Create an `aws_wafv2_web_acl` with `scope = "CLOUDFRONT"` — note this must be provisioned in the `us-east-1` region regardless of where your distribution's origins live.
2. Attach AWS Managed Rule Groups appropriate to your workload (Common Rule Set, Known Bad Inputs, SQLi) and any custom rate-based rules.
3. Set the distribution's `web_acl_id` to the Web ACL's ARN.
4. Start new rules in "Count" mode before switching to "Block" to avoid false-positive outages, then monitor via WAF sampled requests and CloudWatch metrics before enforcing blocking.
5. This is a non-disruptive, in-place association; no distribution replacement required, though propagation of a CloudFront config change can take several minutes.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/WAFEnabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/WAFEnabled.py)
- [AWS: Using AWS WAF to protect CloudFront distributions](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html)
