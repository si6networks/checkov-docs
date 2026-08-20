# CKV_AWS_86: Ensure CloudFront Distribution has Access Logging enabled
## Severity
**LOW** (score: 2.0/10)

Missing CloudFront access logging removes visibility into requests hitting a public-facing distribution, hindering detection of abuse, scraping, or attack attempts, though it does not itself expose data.

## Summary
This check fails when a CloudFront distribution does not have standard access logging configured with a destination S3 bucket.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::CloudFront::Distribution` (CloudFormation), `aws_cloudfront_distribution` (Terraform)
- **Check type:** resource

## Why it matters
CloudFront sits at the edge of your public-facing content delivery, so its access logs (edge location, requester IP, requested URI, response status, referrer, and user agent for every request) are often the earliest and most complete record of how the internet is interacting with your application — including reconnaissance activity, bot traffic, WAF-bypass attempts, and DDoS-style request floods. Without access logs, you cannot retroactively investigate a spike in errors, identify the source of a content-scraping campaign, correlate a security incident's timeline against edge-level request patterns, or verify whether a suspected leaked/pre-signed URL was actually used. Since CloudFront can front APIs, S3-hosted static content, or full application origins, its logs frequently provide the only visibility available before requests reach — or are blocked by — a WAF or backend service.

## How Checkov evaluates this
Both implementations extend `BaseResourceValueCheck` with expected value `ANY_VALUE` (pass as soon as a bucket destination is set, regardless of its value):
- **CloudFormation:** inspects `Properties/DistributionConfig/Logging/Bucket`. Fails if the `Logging` config block or its `Bucket` field is absent.
- **Terraform:** inspects `logging_config/[0]/bucket`. Fails if the `logging_config` block is absent or has no `bucket` value.

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "site" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id   = "site-origin"
  }

  default_cache_behavior {
    target_origin_id       = "site-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods         = ["GET", "HEAD"]
    cached_methods           = ["GET", "HEAD"]
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
resource "aws_s3_bucket" "cf_logs" {
  bucket = "site-cloudfront-access-logs"
}

resource "aws_cloudfront_distribution" "site" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id   = "site-origin"
  }

  default_cache_behavior {
    target_origin_id       = "site-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods         = ["GET", "HEAD"]
    cached_methods           = ["GET", "HEAD"]
  }

  logging_config {
    bucket          = aws_s3_bucket.cf_logs.bucket_domain_name
    include_cookies = false
    prefix          = "site/"
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
1. Create (or designate) an S3 bucket to receive CloudFront access logs.
2. Add a `logging_config` block (Terraform) or `Logging` under `DistributionConfig` (CloudFormation) specifying that bucket's domain name.
3. Set `include_cookies = false` unless you specifically need cookie values in logs (they can contain session tokens — logging them increases the sensitivity of the log bucket itself).
4. Apply a distinct `prefix` per distribution if multiple distributions share a single logging bucket, to keep logs organized.
5. Ensure the logging bucket itself is encrypted, has restrictive access controls, and an appropriate lifecycle/retention policy, since it will accumulate a full record of all public requests to your distribution.
6. This is a non-disruptive, additive configuration; no distribution replacement is required, though CloudFront distribution updates can take several minutes to propagate globally.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudfrontDistributionLogging.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/CloudfrontDistributionLogging.py)
- [Amazon CloudFront access logs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html)
