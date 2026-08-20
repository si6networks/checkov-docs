# CKV_AWS_233: Ensure Create before destroy for ACM certificates

## Severity
**LOW** (score: 2.0/10)

This is an availability/ordering safeguard for certificate replacement rather than a control that closes a confidentiality, integrity, or access-control gap.

## Summary
This check ensures that `aws_acm_certificate` resources declare a `lifecycle { create_before_destroy = true }` block, so that a replacement certificate is issued before the old one is destroyed.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_acm_certificate`

## Why it matters
By default, Terraform destroys a resource before creating its replacement when a change forces re-creation (e.g. a change to `domain_name` or `validation_method` on an ACM certificate). For an ACM certificate that is actively attached to a load balancer, CloudFront distribution, or API Gateway custom domain, destroying it first means there is a window where the certificate backing that endpoint disappears entirely — any TLS handshake attempted during that window fails, causing an availability outage for the associated service. This is a reliability, not purely a security, concern, but it has security implications too: an outage-driven emergency response often leads to rushed, under-reviewed changes (e.g. temporarily disabling TLS enforcement) to restore service quickly. Setting `create_before_destroy = true` ensures Terraform provisions and validates the new certificate first, and only tears down the old one after the new one exists, eliminating the gap.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects `lifecycle[0].create_before_destroy` on the `aws_acm_certificate` resource.
- **PASS** if `create_before_destroy` is explicitly set to `true`.
- **FAIL** if the `lifecycle` block is absent, or `create_before_destroy` is absent or set to `false`. (Unlike some of the value checks in this batch, this one does not treat a missing block as a pass — the lifecycle block must be present with the value set.)

## Non-compliant example
```hcl
resource "aws_acm_certificate" "cert" {
  domain_name       = "app.example.com"
  validation_method = "DNS"
}
```

## Remediated example
```hcl
resource "aws_acm_certificate" "cert" {
  domain_name       = "app.example.com"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}
```

## Remediation steps
1. Add a `lifecycle` block to the `aws_acm_certificate` resource with `create_before_destroy = true`.
2. If the certificate is referenced elsewhere (e.g. `aws_lb_listener.certificate_arn`, `aws_cloudfront_distribution.viewer_certificate.acm_certificate_arn`), make sure those references use the resource's attribute reference (not a hardcoded ARN) so Terraform correctly threads the dependency through the replacement.
3. Be aware that `create_before_destroy` requires unique naming/no unique-per-account constraints that would collide during the brief period both certificates exist — ACM certificates do not have this issue since AWS allows duplicate certs for the same domain to coexist.
4. This change alone does not require replacing the certificate; it only changes how *future* forced replacements are handled.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ACMCertCreateBeforeDestroy.py)
- [Terraform lifecycle meta-argument documentation](https://developer.hashicorp.com/terraform/language/meta-arguments/lifecycle)
