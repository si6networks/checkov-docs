# CKV_AWS_34: Ensure CloudFront Distribution ViewerProtocolPolicy is set to HTTPS
## Severity
**HIGH** (score: 7.0/10)

Allowing CloudFront viewers to connect over plain HTTP (or a non-HTTPS-only viewer protocol policy) exposes content and any session/auth data in transit to interception or tampering by on-path attackers between the client and the edge.

## Summary
This check requires that CloudFront distributions do not set `viewer_protocol_policy` (or `ViewerProtocolPolicy` in CloudFormation) to `allow-all` on their default or ordered cache behaviors, so that viewers are forced to connect over HTTPS rather than being allowed to use plaintext HTTP.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::CloudFront::Distribution` (CloudFormation), `aws_cloudfront_distribution` (Terraform)

## Why it matters
`ViewerProtocolPolicy` controls whether CloudFront requires HTTPS between the end-user's browser and the CloudFront edge location. If set to `allow-all`, clients can request content over plain HTTP, which transmits all data — including session cookies, authentication tokens, and any sensitive content — unencrypted over the network. This exposes users to man-in-the-middle attacks (e.g., on public Wi-Fi or a compromised network segment) where an attacker can passively eavesdrop on traffic or actively inject/modify content in transit (e.g., injecting malicious JavaScript into an HTTP response). It also typically fails modern compliance requirements (PCI DSS, HIPAA) that mandate encryption in transit for any distribution serving sensitive data, and undermines HSTS/mixed-content protections that depend on all traffic actually being HTTPS.

## How Checkov evaluates this
Two implementations, one per framework:

**Terraform (`CloudfrontDistributionEncryption.py`):**
- Checks `default_cache_behavior.viewer_protocol_policy` — if it equals `"allow-all"`, **FAILS**.
- Also checks every entry in `ordered_cache_behavior` — if any behavior's `viewer_protocol_policy` equals `"allow-all"`, **FAILS**.
- Otherwise **PASSES** (i.e., `allow-all` is the only failing value; `redirect-to-https` and `https-only` both pass).

**CloudFormation (`CloudfrontDistributionEncryption.py`):**
- Checks `Properties.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy` — `"allow-all"` → **FAILS**.
- Checks each entry in `Properties.DistributionConfig.CacheBehaviors` — `"allow-all"` on any → **FAILS**.
- If `CacheBehaviors` is present but not a list, returns `UNKNOWN`.
- Otherwise **PASSES**.

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "bad_example" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id    = "s3-origin"
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-origin"
    viewer_protocol_policy = "allow-all"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
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

## Remediated example
```hcl
resource "aws_cloudfront_distribution" "good_example" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id    = "s3-origin"
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-origin"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
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
1. Set `viewer_protocol_policy` to `"redirect-to-https"` (redirects plain HTTP requests to HTTPS) or `"https-only"` (rejects HTTP requests outright) on both `default_cache_behavior` and every `ordered_cache_behavior`.
2. Apply the equivalent fix in CloudFormation by setting `ViewerProtocolPolicy: redirect-to-https` (or `https-only`) under `DefaultCacheBehavior` and each entry in `CacheBehaviors`.
3. `https-only` is stricter and appropriate for APIs or sensitive applications where you never want to serve any content over HTTP, even transiently; `redirect-to-https` is more forgiving for general web content and legacy clients/bookmarks pointing at `http://`.
4. Ensure a valid ACM certificate (or the CloudFront default certificate for `*.cloudfront.net` domains) is configured under `viewer_certificate` so HTTPS actually functions correctly after the change.
5. This is a non-disruptive configuration update — no resource replacement is required, though it does change client-facing behavior (HTTP requests will now redirect or be rejected), so validate no legacy integrations depend on plain HTTP access.

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudfrontDistributionEncryption.py)
- [Checkov CloudFormation check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/CloudfrontDistributionEncryption.py)
- [AWS: Requiring HTTPS for communication between viewers and CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html)
