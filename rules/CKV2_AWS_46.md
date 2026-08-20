# CKV2_AWS_46: Ensure AWS CloudFront Distribution with S3 have Origin Access set to enabled
## Severity
**LOW** (score: 2.0/10)

A CloudFront distribution with an S3 origin lacking Origin Access Identity/Control allows the underlying S3 bucket to potentially be reached directly, bypassing CloudFront's access restrictions, logging, and WAF protections.

## Summary
This check fails when a CloudFront distribution using an S3 bucket as its origin does not have Origin Access Identity (`s3_origin_config`) or Origin Access Control (`origin_access_control_id`) configured, meaning the S3 origin can potentially be reached directly, bypassing CloudFront.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_cloudfront_distribution`

## Why it matters
When CloudFront fronts an S3 bucket without OAI/OAC, the bucket typically must be made at least partially public (or accessible via its regular bucket URL) for CloudFront to fetch objects — which means anyone who discovers or guesses the underlying bucket name can bypass CloudFront entirely and hit S3 directly. This defeats every control you thought CloudFront was providing: WAF rules attached to the distribution, signed URLs/cookies, geo-restrictions, custom domain enforcement, access logging at the edge, and cache-based DDoS absorption all become moot if the origin is reachable directly. Origin Access Identity/Control lets you keep the S3 bucket fully private (no public bucket policy needed) while granting only the CloudFront distribution's specific canonical identity read access, forcing all traffic through the CDN's security controls.

## How Checkov evaluates this
This is a graph-based JSON policy with an `or` of three conditions — any one satisfies the check:
1. The distribution has no graph connection at all to an `aws_s3_bucket` resource (i.e., it isn't an S3-backed distribution in this Terraform config, e.g. it's a custom/ALB origin) — filtered via `resource_type` and a `connection ... not_exists` check.
2. OR `origin.*.s3_origin_config` exists (legacy Origin Access Identity configuration is present).
3. OR `origin.*.origin_access_control_id` exists (modern Origin Access Control is present).
- **FAIL** only when the distribution is connected to an S3 bucket origin in the graph, and neither `s3_origin_config` nor `origin_access_control_id` is set on that origin block (implying a `custom_origin_config` / public website-endpoint style access instead of the private S3 REST-API origin path).

## Non-compliant example
```hcl
resource "aws_s3_bucket" "site" {
  bucket = "example-static-site"
}

resource "aws_cloudfront_distribution" "bad" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id   = "s3-origin"
    # no s3_origin_config, no origin_access_control_id
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
resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "site-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_s3_bucket" "site" {
  bucket = "example-static-site"
}

resource "aws_cloudfront_distribution" "good" {
  enabled = true

  origin {
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id                = "s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.site.id
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

# Bucket policy granting only this distribution's OAC read access
resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudFrontOAC"
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.site.arn}/*"
      Condition = {
        StringEquals = {
          "AWS:SourceArn" = aws_cloudfront_distribution.good.arn
        }
      }
    }]
  })
}
```

## Remediation steps
1. Create an `aws_cloudfront_origin_access_control` resource (preferred over the legacy `aws_cloudfront_origin_access_identity`, which AWS is deprecating).
2. Reference it via `origin_access_control_id` in the distribution's `origin` block.
3. Update the S3 bucket policy to grant `s3:GetObject` only to `cloudfront.amazonaws.com` scoped with an `AWS:SourceArn` condition matching this specific distribution's ARN.
4. Remove any public bucket policy / public-read ACL / static-website-hosting configuration that was previously used to let CloudFront reach the bucket directly.
5. Enable S3 Block Public Access on the bucket now that direct public access is no longer required.
6. If migrating from an existing legacy OAI setup, you can switch to OAC without recreating the distribution, but you must update the bucket policy's principal/condition accordingly.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/CLoudFrontS3OriginConfigWithOAI.json
- AWS docs: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html
