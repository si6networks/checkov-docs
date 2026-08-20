# CKV_AWS_310: Ensure CloudFront distributions should have origin failover configured

## Severity
**MEDIUM** (score: 4.5/10)

Lacking origin failover only affects availability of the CloudFront distribution during an origin outage; it has no direct confidentiality or integrity impact.

## Summary
This check ensures CloudFront distributions define an origin group with failover criteria and at least two member origins, so traffic automatically fails over to a secondary origin if the primary becomes unavailable.

## Applicability
- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_cloudfront_distribution`

## Why it matters
A CloudFront distribution backed by a single origin has no resilience against origin-side outages: if the origin (an S3 bucket, ALB, or custom HTTP backend) becomes unreachable, returns 5xx errors, or the region hosting it has an incident, every viewer request fails with no automatic recovery path. This directly undermines availability guarantees and violates contingency-planning controls (NIST 800-53 CP-10, SC-5(2) — protection against denial of service, SI-13(5) — failover capability). Configuring an origin group with a documented failover criteria (e.g., failover on 500/502/503/504 status codes) lets CloudFront transparently retry a secondary origin, keeping the application available during single-origin failures without any client-visible impact.

## How Checkov evaluates this
The check inspects the `origin_group` block(s) in `aws_cloudfront_distribution`:
- **FAIL** if no `origin_group` block exists at all.
- For each `origin_group` present, it **FAILs** if `failover_criteria` is not set.
- If `failover_criteria` is set, it **FAILs** if the `member` list has fewer than 2 entries (failover requires at least a primary and a secondary origin).
- **PASS** only if every origin group defines `failover_criteria` and has 2+ `member` origins.

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "example" {
  enabled = true

  origin {
    origin_id   = "primary"
    domain_name = aws_s3_bucket.primary.bucket_regional_domain_name

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.oai.cloudfront_access_identity_path
    }
  }

  default_cache_behavior {
    target_origin_id       = "primary"
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
  # No origin_group -> no failover
}
```

## Remediated example
```hcl
resource "aws_cloudfront_distribution" "example" {
  enabled = true

  origin {
    origin_id   = "primary"
    domain_name = aws_s3_bucket.primary.bucket_regional_domain_name
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.oai.cloudfront_access_identity_path
    }
  }

  origin {
    origin_id   = "secondary"
    domain_name = aws_s3_bucket.secondary.bucket_regional_domain_name
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.oai.cloudfront_access_identity_path
    }
  }

  origin_group {                                    # added: failover configuration
    origin_id = "failover-group"

    failover_criteria {
      status_codes = [500, 502, 503, 504]
    }

    member {
      origin_id = "primary"
    }
    member {
      origin_id = "secondary"
    }
  }

  default_cache_behavior {
    target_origin_id       = "failover-group"        # target the group, not a single origin
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

## Remediation steps
1. Provision a secondary origin (a replicated S3 bucket, a standby ALB in another region, etc.) that can serve the same content or a reasonable degraded experience.
2. Add an `origin_group` block referencing both the primary and secondary origins as `member`s (exactly 2 members are required by CloudFront).
3. Set `failover_criteria.status_codes` to the HTTP status codes that should trigger failover (typically 500, 502, 503, 504).
4. Point `default_cache_behavior.target_origin_id` (and any `ordered_cache_behavior`) at the `origin_group`'s `origin_id`, not directly at the primary origin.
5. If the secondary origin is an S3 bucket, ensure cross-region replication keeps it in sync with the primary bucket.
6. Test failover by temporarily disabling access to the primary origin and confirming CloudFront serves from the secondary.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudfrontDistributionOriginFailover.py
- AWS docs: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/high_availability_origin_failover.html
