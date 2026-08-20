# CKV_AWS_174: Verify CloudFront Distribution Viewer Certificate is using TLS v1.2 or higher

## Severity
**HIGH** (score: 7.5/10)

Allowing CloudFront viewer connections below TLS 1.2 permits use of deprecated, cryptographically weak protocol/cipher combinations, enabling protocol-downgrade and man-in-the-middle attacks against data in transit to end users.

## Summary
This check requires that a CloudFront distribution's viewer certificate configuration enforces a minimum TLS protocol version of 1.2 or higher for connections between end-users (viewers) and CloudFront, rejecting the CloudFront default certificate and any protocol policy allowing TLS 1.0/1.1.

## Applicability
- **Terraform**: `aws_cloudfront_distribution`
- **CloudFormation**: `AWS::CloudFront::Distribution`

## Why it matters
TLS 1.0 and TLS 1.1 have well-documented cryptographic weaknesses (e.g. vulnerability to BEAST and POODLE-adjacent attacks, weak cipher suite support, no support for modern AEAD ciphers) and have been deprecated by major browsers, PCI-DSS (which mandated migration off early TLS since 2018), and IETF (TLS 1.0/1.1 formally deprecated via RFC 8996). A CloudFront distribution that allows these older protocol versions exposes end-users to downgrade attacks and man-in-the-middle risks on the viewer-to-CloudFront leg of the connection, and it will fail compliance audits (PCI-DSS, SOC 2, etc.) that explicitly require disabling weak TLS versions.

Additionally, CloudFront's "default certificate" (the `*.cloudfront.net` shared cert) does not allow you to select a minimum protocol version at all — using it means you're stuck with CloudFront's broadest compatibility settings, which historically include weaker TLS versions for legacy client support. Using your own ACM certificate with an explicit `MinimumProtocolVersion` is required to actually enforce TLS 1.2+.

## How Checkov evaluates this
Both implementations inspect the distribution's viewer certificate configuration (`viewer_certificate` in Terraform, `Properties.DistributionConfig.ViewerCertificate` in CloudFormation):
- If `cloudfront_default_certificate` / `CloudFrontDefaultCertificate` is `true`, the check **FAILS** immediately and explicitly — because you cannot set a minimum protocol version while using the CloudFront default certificate.
- Otherwise, it reads `minimum_protocol_version` / `MinimumProtocolVersion` and validates it against the regex `^TLSv1\.(?:2|3)_\d{4}$` — i.e. it must be a value like `TLSv1.2_2021` or `TLSv1.2_2019`, not `TLSv1` or `TLSv1.1_2016`. If the value matches this pattern, the check **PASSES**; otherwise (including if the field is missing, malformed, or set to an older TLS version) it **FAILS**.
- Missing or malformed `viewer_certificate`/`ViewerCertificate` structures (not a proper dict/block) also result in a **FAIL** by default in this check's logic.

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  # ... origin, default_cache_behavior, restrictions omitted for brevity ...

  viewer_certificate {
    cloudfront_default_certificate = true
    # No custom cert -> cannot enforce TLS 1.2+, check fails
  }
}
```

## Remediated example
```hcl
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  # ... origin, default_cache_behavior, restrictions omitted for brevity ...

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.cdn.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"  # added, replaces default certificate
  }
}
```

## Remediation steps
1. Provision (or import) an ACM certificate in `us-east-1` (required for CloudFront) for your custom domain, and reference it via `acm_certificate_arn` instead of `cloudfront_default_certificate = true`.
2. Set `minimum_protocol_version` to a secure value such as `"TLSv1.2_2021"` (recommended current baseline) — values matching `TLSv1.2_YYYY` or `TLSv1.3_YYYY` pass.
3. Set `ssl_support_method` (commonly `"sni-only"`) as required when specifying a custom ACM certificate.
4. Note this requires the distribution to be associated with a custom domain via `aliases` — the CloudFront default certificate cannot be replaced with a custom minimum protocol version while still using `*.cloudfront.net` as the serving domain.
5. Test client compatibility before rolling out — enforcing TLS 1.2+ will reject connections from very old clients (e.g. Windows XP, ancient IoT devices) still negotiating TLS 1.0/1.1.
6. This change can be applied to an existing distribution without full recreation, but CloudFront distribution updates can take significant time to propagate globally (tens of minutes).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudfrontTLS12.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/CloudFrontTLS12.py
- AWS docs: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html
