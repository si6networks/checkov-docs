# CKV_AWS_374: Ensure AWS CloudFront web distribution has geo restriction enabled

## Severity
**LOW** (score: 2.0/10)

Missing CloudFront geo restriction is an access-control gap that limits abuse from specific regions rather than a primary security boundary, so its absence increases exposure to fraud/abuse traffic but does not by itself grant unauthorized data or system access.

## Summary
This check ensures that an Amazon CloudFront distribution has geographic (geo) restriction configured rather than left disabled, so content delivery can be limited to approved countries.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_cloudfront_distribution`

## Why it matters
CloudFront geo restriction (geoblocking) lets you allow or deny access to your distribution's content based on the viewer's geographic location. When geo restriction is left at `restriction_type = "none"`, the distribution serves content to any country, which:

- Prevents you from enforcing content-licensing or export-control obligations that require blocking specific countries.
- Removes a coarse but useful defense-in-depth layer against distributed abuse or scraping originating from regions you don't serve.
- Can violate regulatory requirements (e.g., data residency or sanctions compliance) that mandate blocking access from certain jurisdictions.

Leaving geo restriction disabled doesn't create a direct vulnerability on its own, but for distributions where compliance or licensing dictates geographic limits, an unrestricted distribution silently fails to enforce that boundary.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck`. It inspects the nested attribute path:

```
restrictions/[0]/geo_restriction/[0]/restriction_type
```

The check **FAILS** only when this value equals the forbidden value `"none"`. Any other value (`"whitelist"` or `"blacklist"`), or the attribute simply being absent (in some negative-value-check semantics, absence is treated as passing since there's no forbidden value present), causes a PASS.

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "example" {
  # ... origin, default_cache_behavior, etc. omitted for brevity ...

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
  # ... origin, default_cache_behavior, etc. omitted for brevity ...

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
```

## Remediation steps
1. Decide whether your use case needs a `whitelist` (allow only listed countries) or `blacklist` (block only listed countries) approach.
2. Set `restriction_type` to `"whitelist"` or `"blacklist"` in the `geo_restriction` block.
3. Populate `locations` with the relevant ISO 3166-1-alpha-2 country codes.
4. If your distribution genuinely needs to serve every country with no restriction, this check will still flag it — consider adding a Checkov suppression comment (`checkov:skip=CKV_AWS_374`) with a justification, since not every distribution has a legitimate geo-compliance need.
5. Re-apply the Terraform plan; geo restriction changes propagate through normal CloudFront distribution updates and do not require resource replacement.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudFrontGeoRestrictionDisabled.py)
- [AWS CloudFront geographic restrictions documentation](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html)
