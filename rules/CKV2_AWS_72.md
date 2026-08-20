# CKV2_AWS_72: Ensure AWS CloudFront origin protocol policy enforces HTTPS-only

## Severity
**HIGH** (score: 7.0/10)

Allowing CloudFront to communicate with a custom origin over plaintext HTTP exposes request/response traffic between the CDN and origin to interception or tampering, a missing encryption-in-transit control for potentially sensitive application data.

## Summary
This check requires CloudFront distributions with a custom origin to set `OriginProtocolPolicy`/`origin_protocol_policy` to `https-only`, so CloudFront always connects to the origin over HTTPS rather than allowing (or exclusively using) plaintext HTTP.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::CloudFront::Distribution` (CloudFormation), `aws_cloudfront_distribution` (Terraform) — specifically origins using `CustomOriginConfig`/`custom_origin_config`

## Why it matters
CloudFront sits between end users and your origin server (an ALB, EC2 instance, or other HTTP(S) endpoint). If the origin protocol policy is `http-only` or `match-viewer`, traffic between the CloudFront edge and your origin can travel unencrypted, even though the front-facing viewer connection to CloudFront is HTTPS. This creates a plaintext segment on a network path an attacker may be able to observe — anyone with visibility into the path between the CloudFront edge location and your origin (a misconfigured VPC peering, a compromised host on a shared subnet, or in the case of `match-viewer`, any client that itself connects over plain HTTP) can potentially intercept or tamper with request/response data, including session cookies, API tokens, and sensitive payloads, defeating the purpose of terminating TLS at CloudFront in the first place. Enforcing `https-only` for the origin closes this gap, ensuring end-to-end encryption for the entire request path rather than only the viewer-facing half.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy) structured as an `or` of pass conditions (i.e., the check is designed to also skip cases where it doesn't meaningfully apply):
1. **PASSES** if the distribution is disabled (`Enabled`/`enabled == false`) — a disabled distribution isn't serving traffic.
2. **PASSES** if no origin has a `CustomOriginConfig`/`custom_origin_config` at all (e.g., all origins are S3 origins using OAC/OAI, which don't use this protocol-policy setting).
3. Otherwise, **PASSES** only if, among origins whose `OriginProtocolPolicy` is *not* `https-only`, none of their domain names contain `.mediastore.`, `.mediapackage.`, or `.elb.` (these are AWS-managed origin types that are explicitly carved out/allowed to use non-`https-only` policies in this check's logic, likely reflecting real-world constraints on media-service or classic ELB origins).

In effect: for any custom origin whose domain name is a "normal" origin (not MediaStore, MediaPackage, or an ELB-based domain), `OriginProtocolPolicy` must be `https-only`, or the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_cloudfront_distribution" "app" {
  enabled = true

  origin {
    domain_name = aws_lb.app.dns_name   # generic ALB origin, non-.elb. custom domain via Route53 alias record
    origin_id   = "app-origin"

    custom_origin_config {
      http_port              = 80
      https_port              = 443
      origin_protocol_policy  = "match-viewer"   # allows plaintext HTTP -> FAILS
      origin_ssl_protocols    = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "app-origin"
    viewer_protocol_policy  = "redirect-to-https"
    allowed_methods         = ["GET", "HEAD"]
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
resource "aws_cloudfront_distribution" "app" {
  enabled = true

  origin {
    domain_name = aws_lb.app.dns_name
    origin_id   = "app-origin"

    custom_origin_config {
      http_port              = 80
      https_port              = 443
      origin_protocol_policy  = "https-only"      # changed: force HTTPS to origin
      origin_ssl_protocols    = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "app-origin"
    viewer_protocol_policy  = "redirect-to-https"
    allowed_methods         = ["GET", "HEAD"]
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
1. For every origin using `custom_origin_config`, set `origin_protocol_policy = "https-only"`.
2. Ensure the origin (ALB, EC2, on-prem endpoint) actually has a valid HTTPS listener with a certificate CloudFront trusts — switching to `https-only` will break the distribution if the origin doesn't terminate TLS.
3. Set `origin_ssl_protocols` to a modern minimum (e.g., `["TLSv1.2"]`) to avoid negotiating weak/deprecated TLS versions to the origin.
4. If the origin is a classic Elastic Load Balancer or AWS MediaStore/MediaPackage endpoint, review whether `https-only` is achievable for your setup — the check itself carves out some leniency for `.elb.`, `.mediastore.`, and `.mediapackage.` domain patterns, but `https-only` end-to-end is still the stronger posture where feasible.
5. Applying this change to an existing distribution does not require replacement, but CloudFront distribution updates can take 15+ minutes to propagate globally — validate origin HTTPS readiness before deploying to avoid an outage window.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/CloudfrontOriginNotHTTPSOnly.json
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/graph_checks/CloudfrontOriginNotHTTPSOnly.json
- AWS docs: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html
