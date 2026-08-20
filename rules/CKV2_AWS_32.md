# CKV2_AWS_32: Ensure CloudFront distribution has a response headers policy attached
## Severity
**MEDIUM** (score: 5.0/10)

Missing a CloudFront response headers policy means security headers (e.g. HSTS, X-Content-Type-Options, CSP) may not be enforced, increasing exposure to client-side attacks like clickjacking or MIME-sniffing but not itself a direct breach.

## Summary
This check ensures that every `aws_cloudfront_distribution` has an `aws_cloudfront_response_headers_policy` (or a referenced `data.aws_cloudfront_response_headers_policy`) attached, so that the distribution injects security-relevant HTTP response headers.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_cloudfront_distribution` (connected `aws_cloudfront_response_headers_policy` or `data.aws_cloudfront_response_headers_policy`)
- **Check type:** Graph-based connection check

## Why it matters
CloudFront response headers policies are the mechanism for injecting security headers such as `Strict-Transport-Security` (HSTS, forcing HTTPS and preventing downgrade/SSL-stripping attacks), `X-Content-Type-Options: nosniff` (preventing MIME-sniffing attacks), `X-Frame-Options`/`frame-ancestors` (preventing clickjacking), `Content-Security-Policy` (mitigating XSS and data-injection attacks), and CORS headers. Without a response headers policy attached, a distribution serves whatever headers the origin sends (or none at all for these), meaning browsers viewing the site lack these defense-in-depth protections even if the origin application itself doesn't set them consistently — leaving users exposed to clickjacking, content-sniffing exploits, cookie/session hijacking via mixed content, and reduced protection against cross-site scripting. Centralizing security headers at the CDN layer via a response headers policy ensures consistent enforcement regardless of what the origin returns.

## How Checkov evaluates this
This is a graph check (`CloudFrontHasResponseHeadersPolicy.json`). It filters for resources of type `aws_cloudfront_distribution`, and passes only if a graph connection exists from that distribution to either an `aws_cloudfront_response_headers_policy` resource or a `data.aws_cloudfront_response_headers_policy` data source (i.e., a cache behavior's `response_headers_policy_id` argument references one of these). A distribution with no `response_headers_policy_id` set on any of its cache behaviors fails.

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "site" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id   = "s3-site"
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-site"
    viewer_protocol_policy = "redirect-to-https"
    # No response_headers_policy_id set
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

## Remediated example
```hcl
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name = "security-headers-policy"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 63072000
      include_subdomains          = true
      override                    = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    xss_protection {
      protection = true
      mode_block = true
      override   = true
    }
  }
}

resource "aws_cloudfront_distribution" "site" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id   = "s3-site"
  }

  default_cache_behavior {
    allowed_methods            = ["GET", "HEAD"]
    cached_methods              = ["GET", "HEAD"]
    target_origin_id            = "s3-site"
    viewer_protocol_policy      = "redirect-to-https"
    response_headers_policy_id  = aws_cloudfront_response_headers_policy.security_headers.id
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
1. Create an `aws_cloudfront_response_headers_policy` (custom) or reference one of the AWS-managed policies via `data "aws_cloudfront_response_headers_policy"` (e.g., the managed `Managed-SecurityHeadersPolicy`).
2. Configure `security_headers_config` with HSTS, `X-Content-Type-Options`, `X-Frame-Options`, XSS protection, and referrer policy as appropriate for your application.
3. Set `response_headers_policy_id` on every `default_cache_behavior` and `ordered_cache_behavior` block within the distribution — the check requires the connection to exist, so behaviors without it individually remain unprotected even if others have it.
4. If using a `Content-Security-Policy`, tailor it carefully to your application's actual script/style/frame sources to avoid breaking functionality; start in report-only mode if unsure.
5. No resource replacement is required — this is a non-destructive, in-place update to the distribution's cache behavior configuration, though CloudFront distribution updates can take several minutes to propagate globally.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/CloudFrontHasResponseHeadersPolicy.json)
- [AWS CloudFront response headers policies documentation](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-response-headers.html)
