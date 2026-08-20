# CKV_AWS_216: Ensure CloudFront distribution is enabled
## Severity
**LOW** (score: 2.0/10)

A disabled CloudFront distribution is an availability/configuration-hygiene issue rather than a direct attack path, since a disabled distribution serves no traffic at all.

## Summary
This check ensures that an `aws_cloudfront_distribution` resource has its `enabled` attribute set to `true`, so the distribution is actively serving traffic rather than sitting disabled while still billed and provisioned.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_cloudfront_distribution`

## Why it matters
While this is framed primarily as a hygiene/reliability check rather than a direct vulnerability, a disabled CloudFront distribution left in Terraform state creates operational and security risk in practice: infrastructure-as-code that provisions a distribution and then leaves it (or flips it to) disabled can indicate configuration drift between what operators intend and what is actually deployed — a disabled distribution silently stops serving content or enforcing its associated protections (e.g. WAF web ACL association, custom SSL/TLS termination, geo-restriction, signed URL/cookie requirements) without an obvious outage signal if traffic is later rerouted elsewhere or a dependent origin is directly exposed. Ensuring `enabled = true` (or explicit intentional review when `false`) keeps the deployed state consistent with the security controls the distribution is meant to provide, and avoids "it's there but not actually protecting anything" gaps.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `enabled` attribute of `aws_cloudfront_distribution`:
- If `enabled` is `true`, the check **PASSES**.
- If `enabled` is `false` or the value otherwise doesn't match, the check **FAILS**.
- (Default `BaseResourceValueCheck` missing-block behavior applies since no override is specified.)

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "example" {
  enabled = false

  origin {
    domain_name = aws_s3_bucket.example.bucket_regional_domain_name
    origin_id   = "example-origin"
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "example-origin"
    viewer_protocol_policy = "redirect-to-https"
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
resource "aws_cloudfront_distribution" "example" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.example.bucket_regional_domain_name
    origin_id   = "example-origin"
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "example-origin"
    viewer_protocol_policy = "redirect-to-https"
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
1. Set `enabled = true` on the `aws_cloudfront_distribution` resource.
2. If the distribution is intentionally disabled (e.g. it's a placeholder or being decommissioned), consider removing the resource from Terraform entirely instead of leaving a disabled distribution in state, or add a documented Checkov suppression comment explaining why it must stay disabled.
3. Verify any dependent DNS records (Route 53 alias records) or WAF associations still make sense once the distribution is re-enabled.
4. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudfrontDistributionEnabled.py)
- [Terraform AWS Provider: aws_cloudfront_distribution](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution)
