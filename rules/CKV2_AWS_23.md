# CKV2_AWS_23: Route53 A Record has Attached Resource
## Severity
**HIGH** (score: 7.5/10)

A dangling Route 53 alias pointing to a deprovisioned resource enables subdomain takeover, letting an attacker serve phishing or malicious content under the organization's trusted domain and abuse same-origin trust.

## Summary
This check ensures that every Route 53 `A` record with an `alias` block actually points to a real, connected AWS resource (e.g., a load balancer, EC2 instance, CloudFront distribution) rather than being a dangling record with no live target.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_route53_record` (type `A` only)
- **Check type:** Graph-based connection/attribute check

## Why it matters
A Route 53 `A`-record alias that no longer resolves to an actual, owned AWS resource is a classic setup for **subdomain takeover**. If the alias target (e.g., an S3 bucket website endpoint, an Elastic Beanstalk environment, an ELB/ALB, a CloudFront distribution, or an EIP) is deleted but the DNS record is left in place, an attacker can often provision a new resource of the same type in the same region and claim the exact hostname referenced by the target, since AWS resource endpoints (like S3 bucket static-site URLs or ELB DNS names) are often globally reusable/predictable. This lets an attacker serve arbitrary content — including phishing pages or malware — under your organization's trusted domain name, bypass same-origin protections, and potentially steal cookies or OAuth tokens scoped to your domain. Ensuring the record is genuinely wired to a live, Terraform-managed (or otherwise clearly intentional) resource closes this "dangling DNS" gap.

## How Checkov evaluates this
This is a graph check (`Route53ARecordAttachedResource.json`). For every `aws_route53_record` of `type = "A"`, it passes if **any** of the following is true:
- The `alias.name` attribute's value contains the substring `"module"` (i.e., it is derived from a module output — Checkov can't trace through the module boundary, so it is treated as intentionally dynamic and given a pass), OR
- `alias.name` contains `"data."` (i.e., it references a Terraform data source), OR
- `alias.name` contains `"var."` (i.e., it references a Terraform input variable), OR
- A graph connection exists from the `aws_route53_record` to one of: `aws_instance`, `aws_eip`, `aws_elb`, `aws_lb`, `aws_alb`, `aws_route53_record` (another record), `aws_s3_bucket`, `aws_api_gateway_domain_name`, `aws_elastic_beanstalk_environment`, `aws_vpc_endpoint`, `aws_globalaccelerator_accelerator`, `aws_cloudfront_distribution`, `aws_db_instance`, `aws_apigatewayv2_domain_name`, `aws_lightsail_instance`, or `aws_lightsail_static_ip`.

If none of these conditions hold — e.g., the alias target is a hardcoded/static string that doesn't reference any resource Checkov can trace — the check fails.

## Non-compliant example
```hcl
resource "aws_route53_record" "app" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "app.example.com"
  type    = "A"

  alias {
    # Hardcoded target string, not connected to any managed resource
    name                   = "old-elb-1234567890.us-east-1.elb.amazonaws.com"
    zone_id                = "Z35SXDOTRQ7X7K"
    evaluate_target_health = true
  }
}
```

## Remediated example
```hcl
resource "aws_lb" "app" {
  name               = "app-lb"
  load_balancer_type = "application"
  subnets            = var.subnet_ids
}

resource "aws_route53_record" "app" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "app.example.com"
  type    = "A"

  alias {
    # Points to a Terraform-managed resource — graph connection satisfies the check
    name                   = aws_lb.app.dns_name
    zone_id                = aws_lb.app.zone_id
    evaluate_target_health = true
  }
}
```

## Remediation steps
1. Audit every `aws_route53_record` of type `A` with an `alias` block.
2. Replace hardcoded alias target strings with references to the actual Terraform-managed resource (`aws_lb.x.dns_name`, `aws_cloudfront_distribution.x.domain_name`, `aws_s3_bucket.x.website_endpoint`, etc.) so Checkov (and future maintainers) can trace ownership.
3. If the target is genuinely external or provisioned outside this Terraform root (e.g., via a module or a `data` source), reference it through `var.` or `data.` so the intent is explicit — the check already treats these as acceptable.
4. Periodically audit DNS records against currently-provisioned AWS resources and remove any orphaned alias records pointing at deleted/deprovisioned endpoints — this is the more important real-world mitigation, since IaC-time checks can't detect drift introduced after apply (e.g., manual resource deletion later).
5. Consider enabling AWS tools/services that detect dangling DNS records (e.g., third-party subdomain-takeover scanners) as a defense-in-depth measure beyond static IaC scanning.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/Route53ARecordAttachedResource.json)
- [AWS Route 53 alias records documentation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-choosing-alias-non-alias.html)
