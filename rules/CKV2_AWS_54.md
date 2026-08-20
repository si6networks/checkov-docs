# CKV2_AWS_54: Ensure AWS CloudFront distribution is using secure SSL protocols for HTTPS communication
## Severity
**HIGH** (score: 7.4/10)

Allowing SSLv3 on a CloudFront custom origin permits a protocol with known cryptographic weaknesses (e.g., POODLE), enabling potential downgrade and plaintext-recovery attacks on data in transit.

## Summary
This check fails when a CloudFront distribution's custom origin configuration allows `SSLv3` as one of the accepted `origin_ssl_protocols` for connecting from CloudFront to the origin server.

## Applicability
- **IaC framework:** Terraform
- **Resource/entity types:** `aws_cloudfront_distribution`

## Why it matters
SSLv3 is a deprecated, fundamentally broken protocol — it is vulnerable to the POODLE attack (CVE-2014-3566), which allows a man-in-the-middle attacker to decrypt portions of the encrypted traffic by exploiting SSLv3's use of CBC-mode padding, and it lacks the cipher suite/handshake security improvements of TLS 1.0+. Every major browser and security standard deprecated SSLv3 years ago, yet if `origin_ssl_protocols` on a custom origin still lists `SSLv3`, an attacker capable of intercepting or influencing the connection between the CloudFront edge and your origin (e.g. via a compromised network path, DNS manipulation, or origin server downgrade) could force protocol negotiation down to SSLv3 and mount a padding-oracle attack to recover portions of otherwise-encrypted origin traffic — data that may include session tokens, API keys, or PII flowing between the CDN and the backend origin server.

## How Checkov evaluates this
This is a graph-based JSON policy checking a single attribute:
- **Attribute checked:** `origin.*.custom_origin_config.origin_ssl_protocols` on `aws_cloudfront_distribution`
- **Operator:** `not_contains`, value `"SSLv3"`
- **PASS** if no origin's `origin_ssl_protocols` list contains `SSLv3`.
- **FAIL** if any origin explicitly includes `SSLv3` in its list of allowed protocols for CloudFront-to-origin connections.
- Note: this check only applies to `custom_origin_config` (used for non-S3 / non-S3-REST-API origins such as ALBs, EC2, or external HTTP servers); it does not evaluate the `viewer_certificate.minimum_protocol_version` (which governs client-to-CloudFront TLS — see CKV2_AWS_42/CKV_AWS_174) nor S3-origin configurations, which don't expose `origin_ssl_protocols` at all.

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "bad" {
  enabled = true

  origin {
    domain_name = "origin.example.com"
    origin_id   = "custom-origin"

    custom_origin_config {
      http_port              = 80
      https_port              = 443
      origin_protocol_policy  = "https-only"
      origin_ssl_protocols    = ["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "custom-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods         = ["GET", "HEAD"]
    cached_methods           = ["GET", "HEAD"]
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
resource "aws_cloudfront_distribution" "good" {
  enabled = true

  origin {
    domain_name = "origin.example.com"
    origin_id   = "custom-origin"

    custom_origin_config {
      http_port              = 80
      https_port              = 443
      origin_protocol_policy  = "https-only"
      origin_ssl_protocols    = ["TLSv1.2"] # SSLv3 removed; modern-only protocol
    }
  }

  default_cache_behavior {
    target_origin_id       = "custom-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods         = ["GET", "HEAD"]
    cached_methods           = ["GET", "HEAD"]
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
1. Remove `SSLv3` from the `origin_ssl_protocols` list in every `custom_origin_config` block.
2. Ideally restrict the list to `TLSv1.2` only; include `TLSv1.1`/`TLSv1` only if the origin server genuinely cannot be upgraded to support TLS 1.2 (rare in modern environments, and itself a risk worth remediating on the origin side).
3. Confirm the origin server is actually configured to negotiate the protocols you keep in the list — removing SSLv3 from CloudFront's allowed list doesn't help if the origin still only speaks SSLv3.
4. Test the distribution after the change (a CloudFront config update, not a resource replacement) to confirm origin fetches still succeed over the remaining protocol versions.
5. Also review `viewer_certificate.minimum_protocol_version` separately to ensure client-facing TLS is similarly modern (this check only covers the origin-facing side).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/CloudFrontUsesSecureProtocolsForHTTPS.json
- AWS docs: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/to-custom-origin.html
