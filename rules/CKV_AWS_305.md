# CKV_AWS_305: Ensure CloudFront distribution has a default root object configured
## Severity
**MEDIUM** (score: 4.5/10)

This check verifies a CloudFront distribution has a default root object configured; without one, requests to the distribution root can enumerate bucket/origin contents or return unintended objects, a minor information-exposure/misconfiguration risk rather than a direct compromise path.

## Summary
This check ensures an `aws_cloudfront_distribution` resource sets a `default_root_object` (e.g., `index.html`) so requests to the distribution's root path return a specific, intended object rather than being unhandled.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_cloudfront_distribution`

## Why it matters
When a CloudFront distribution has no `default_root_object` configured, a request to the bare root URL (e.g., `https://d123.cloudfront.net/`) is passed straight through to the origin without CloudFront substituting a default file. Depending on the origin type, this can result in directory listing being exposed (if the origin is an S3 bucket configured for static website hosting and listing is enabled), a confusing 403/404 error that leaks origin implementation details, or — worse — an origin that responds to the bare path with unintended content or behavior it wasn't designed to serve safely. Explicit control over what is served at the root reduces the attack surface for information disclosure and unpredictable error handling, and it's called out under NIST 800-53 SC-7(11)/SC-7(16) as part of boundary protection expectations for how a service responds to malformed or edge-case requests at its perimeter.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (Python check) using `ANY_VALUE` as the expected value. It inspects the `default_root_object` attribute:
- **PASS** if `default_root_object` is set to any non-empty value.
- **FAIL** if the attribute is missing or empty.

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "site" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id   = "s3-site"
  }

  default_cache_behavior {
    target_origin_id       = "s3-site"
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
  # default_root_object not set -> check FAILS
}
```

## Remediated example
```hcl
resource "aws_cloudfront_distribution" "site" {
  enabled              = true
  default_root_object  = "index.html"   # explicit default served at the root

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id   = "s3-site"
  }

  default_cache_behavior {
    target_origin_id       = "s3-site"
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
1. Add `default_root_object = "index.html"` (or the appropriate root file for your application) to the `aws_cloudfront_distribution` resource.
2. Verify the specified object actually exists at the origin, otherwise root requests will now 404 against a valid but missing key.
3. For SPA-style applications where deep-linked routes should also fall back to `index.html`, pair this with a CloudFront Function or Lambda@Edge (or an S3 static-website `error_document`) since `default_root_object` only affects the bare root path, not arbitrary sub-paths.
4. Confirm the S3 origin does not have public bucket listing enabled as an additional safeguard against directory enumeration.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudfrontDistributionDefaultRoot.py)
