# CKV2_AWS_71: Ensure AWS ACM Certificate domain name does not include wildcards

## Severity
**LOW** (score: 2.0/10)

A wildcard ACM certificate broadens the scope of what a single compromised private key can impersonate across subdomains, a real but indirect risk that depends on separate key compromise or subdomain takeover to be exploited.

## Summary
This check requires that ACM certificates neither specify a wildcard (`*`) in their primary `DomainName`/`domain_name` nor in any entry of `SubjectAlternativeNames`/`subject_alternative_names`.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::CertificateManager::Certificate` (CloudFormation), `aws_acm_certificate` (Terraform)

## Why it matters
Wildcard certificates (e.g., `*.example.com`) authenticate *any* subdomain under the covered domain with a single private key. This concentrates risk: compromise of the private key for one service (a forgotten dev subdomain, a low-priority internal tool) grants an attacker the ability to impersonate every subdomain covered by the wildcard — including production, payment, and authentication endpoints — enabling man-in-the-middle attacks, phishing with a valid TLS certificate, or session hijacking across the whole domain estate. Wildcards also violate least-privilege at the PKI layer: a single certificate/key pair ends up trusted for services with very different security postures and teams managing them, and rotating or revoking the certificate to respond to a compromise now impacts every subdomain simultaneously rather than just the affected service. Issuing per-subdomain (or per-service, via SANs listing exact names) certificates limits blast radius and keeps certificate lifecycle management scoped to the actual service that needs it.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy), identical in structure for both frameworks, requiring both of the following on the certificate resource:
1. `DomainName` / `domain_name` **does not contain** the literal `*` character.
2. Either `SubjectAlternativeNames` / `subject_alternative_names` **does not exist** at all, OR none of the entries in that list **contains** `*` (checked via a wildcard match across the list).

If the primary domain name contains `*`, or any SAN entry contains `*`, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_acm_certificate" "app" {
  domain_name       = "*.example.com"     # wildcard primary domain -> FAILS
  validation_method = "DNS"

  subject_alternative_names = [
    "example.com"
  ]
}
```

## Remediated example
```hcl
resource "aws_acm_certificate" "app" {
  domain_name       = "app.example.com"   # exact hostname
  validation_method = "DNS"

  subject_alternative_names = [
    "www.example.com",
    "api.example.com"
  ]                                        # explicit SANs, no wildcards
}
```

## Remediation steps
1. Replace wildcard `domain_name`/`DomainName` values with the specific hostname the certificate actually protects.
2. Enumerate every subdomain that needs coverage and list them explicitly in `subject_alternative_names`/`SubjectAlternativeNames` instead of relying on a wildcard to cover "whatever comes up later."
3. If the number of subdomains is large or dynamic (e.g., per-tenant subdomains), consider issuing certificates per-service via automation (ACM + DNS validation is free and can be scripted) rather than falling back to a wildcard for convenience.
4. Where a wildcard is unavoidable (e.g., a genuinely dynamic multi-tenant subdomain pattern), compensate with tighter operational controls: dedicated key storage, restricted IAM access to the ACM resource, and monitoring for anomalous certificate usage — and treat this Checkov finding as a suppressed/accepted-risk exception with documented justification rather than silently skipping it.
5. Requesting a new (non-wildcard) certificate and updating references (ALB listener, CloudFront distribution) to it is generally low-risk, but validate the new certificate's DNS validation records are in place before cutting over, to avoid a TLS validation gap.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/ACMWildcardDomainName.json
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/graph_checks/ACMWildcardDomainName.json
- AWS docs: https://docs.aws.amazon.com/acm/latest/userguide/acm-bestpractices.html
