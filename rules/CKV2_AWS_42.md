# CKV2_AWS_42: Ensure AWS CloudFront distribution uses custom SSL certificate
## Severity
**MEDIUM** (score: 4.5/10)

Relying on the default CloudFront certificate instead of a custom ACM/IAM certificate is a weaker TLS/branding posture but traffic is still encrypted, so the risk is limited to certificate management and trust concerns rather than data exposure.

## Summary
This check fails when a CloudFront distribution's `viewer_certificate` block relies on the default CloudFront certificate instead of a custom certificate imported via IAM or issued/managed via ACM.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_cloudfront_distribution`

## Why it matters
The default `*.cloudfront.net` certificate only supports the shared CloudFront domain — it cannot present a certificate for your own custom domain name, and by default it also restricts the minimum TLS protocol version and cipher suite flexibility (it forces `TLSv1` support for backward compatibility with legacy clients unless a custom certificate with a stricter `minimum_protocol_version` is configured). Using a custom certificate (via ACM or an uploaded IAM server certificate) lets you serve traffic under your own domain with your own trust chain, and — critically — lets you explicitly select a modern minimum TLS protocol/cipher policy (e.g. `TLSv1.2_2021`), closing off downgrade attacks and use of deprecated, vulnerable protocol versions. Skipping this leaves the distribution's edge-to-client TLS posture at AWS's lowest-common-denominator default rather than an organization-controlled security policy.

## How Checkov evaluates this
This is a graph-based JSON policy that checks the `viewer_certificate` block of `aws_cloudfront_distribution`:
- **PASS** if `viewer_certificate.iam_certificate_id` exists, OR `viewer_certificate.acm_certificate_arn` exists (evaluated as an `or`).
- **FAIL** if neither attribute is set — meaning the distribution is left on `cloudfront_default_certificate = true` (the implicit AWS-managed shared certificate).

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "bad" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id   = "s3-origin"
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
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
```

## Remediated example
```hcl
resource "aws_acm_certificate" "site" {
  provider          = aws.us_east_1 # ACM cert for CloudFront must be in us-east-1
  domain_name       = "www.example.com"
  validation_method = "DNS"
}

resource "aws_cloudfront_distribution" "good" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id   = "s3-origin"
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
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.site.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}
```

## Remediation steps
1. Provision an ACM certificate for your custom domain in `us-east-1` (required for CloudFront), or upload a certificate to IAM if you must use a non-ACM CA.
2. Validate the certificate (DNS or email validation).
3. Set `viewer_certificate.acm_certificate_arn` (or `iam_certificate_id`) instead of `cloudfront_default_certificate = true`.
4. Set `ssl_support_method = "sni-only"` (or `vip` if you need legacy client support, at extra cost) and explicitly set `minimum_protocol_version` to a modern value like `TLSv1.2_2021`.
5. Add an `aliases` block listing the custom domain names the certificate covers, and point DNS (e.g. Route 53 alias record) at the distribution.
6. Changing `viewer_certificate` does not require replacing the distribution, but propagation of the CloudFront config update can take several minutes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/CloudFrontHasCustomSSLCertificate.json
- AWS docs: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html
