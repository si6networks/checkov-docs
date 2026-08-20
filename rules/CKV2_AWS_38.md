# CKV2_AWS_38: Ensure DNSSEC signing is enabled for Amazon Route 53 public hosted zones
## Severity
**MEDIUM** (score: 6.0/10)

Without DNSSEC, a public hosted zone's responses cannot be cryptographically validated by resolvers, leaving the domain open to cache-poisoning and spoofing attacks that can redirect users or intercept mail, though exploitation requires an on-path or cache-poisoning attacker.

## Summary
This check ensures that public Route 53 hosted zones (`aws_route53_zone` with no `vpc` block, i.e., not a private zone) have DNSSEC signing enabled via a connected `aws_route53_hosted_zone_dnssec` resource (and typically an `aws_route53_key_signing_key`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_route53_zone` (connected `aws_route53_hosted_zone_dnssec`, `aws_route53_key_signing_key`, `aws_route53_zone_association`)
- **Category:** Networking

## Why it matters
DNS itself is not authenticated: without DNSSEC, a resolver has no cryptographic way to verify that the DNS responses it receives for your domain actually came from your authoritative name servers and weren't tampered with in transit. This leaves your domain's zone open to cache-poisoning and man-in-the-middle DNS spoofing attacks, where an attacker on the network path (or one who has poisoned a recursive resolver's cache) can return forged A/AAAA/MX/TXT records for your domain — redirecting your users to malicious IP addresses, intercepting email intended for your domain, or defeating certain SPF/DKIM-adjacent anti-spoofing measures that rely on DNS TXT records being trustworthy. DNSSEC adds a chain of cryptographic signatures (via key-signing and zone-signing keys) so validating resolvers can detect and reject tampered responses. This matters most for zones serving public-facing production domains, which is why the check specifically excludes private hosted zones (those with a `vpc` block) — private zones are only resolved within your VPC's internal resolver and are not exposed to the public DNS resolution path this attack targets.

## How Checkov evaluates this
This is a graph check (`Route53ZoneEnableDNSSECSigning.json`) with two PASS branches combined via `or`:
1. The `aws_route53_zone` has a non-empty `vpc` attribute (i.e., it's a **private** hosted zone) → PASS, since DNSSEC applies to public zone resolution and isn't relevant/applicable to private zones.
2. The zone is filtered as `aws_route53_zone`, AND a graph connection exists from that zone to any of: `aws_route53_hosted_zone_dnssec`, `aws_route53_key_signing_key`, or `aws_route53_zone_association` → PASS.

So a public hosted zone (no `vpc` block, or an empty one) fails unless it is connected to a DNSSEC-signing resource (or, per the check's connection list, a zone association resource — reflecting the graph check's connection matching rather than a strict semantic requirement).

## Non-compliant example
```hcl
resource "aws_route53_zone" "public" {
  name = "example.com"
}
# No aws_route53_hosted_zone_dnssec or key-signing key configured
```

## Remediated example
```hcl
resource "aws_route53_zone" "public" {
  name = "example.com"
}

resource "aws_kms_key" "dnssec_ksk" {
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                 = "SIGN_VERIFY"
  policy                    = data.aws_iam_policy_document.dnssec_kms_policy.json
}

resource "aws_route53_key_signing_key" "public_ksk" {
  hosted_zone_id             = aws_route53_zone.public.id
  key_management_service_arn = aws_kms_key.dnssec_ksk.arn
  name                        = "example-com-ksk"
}

resource "aws_route53_hosted_zone_dnssec" "public_dnssec" {
  hosted_zone_id = aws_route53_key_signing_key.public_ksk.hosted_zone_id
  depends_on     = [aws_route53_key_signing_key.public_ksk]
}
```

## Remediation steps
1. Create a customer-managed KMS key with `key_usage = "SIGN_VERIFY"` and an asymmetric key spec supported by Route 53 (e.g., `ECC_NIST_P256`), with a key policy granting Route 53 the necessary `kms:Sign`, `kms:GetPublicKey`, and `kms:DescribeKey` permissions.
2. Create an `aws_route53_key_signing_key` referencing the hosted zone and the KMS key.
3. Create an `aws_route53_hosted_zone_dnssec` resource to enable signing for the zone, depending on the key-signing key being active first.
4. After enabling, retrieve the DS (Delegation Signer) record Route 53 generates and submit it to your domain registrar (the parent zone) to complete the chain of trust — Terraform/Route 53 cannot do this step for you if the registrar is external, since it requires publishing the DS record at the parent/TLD level.
5. Caveat: enabling and especially disabling DNSSEC on a live zone requires careful ordering (disable signing before deleting key-signing keys) to avoid a validation failure window where resolvers reject all responses from the zone as unsigned/invalid; follow AWS's documented enable/disable procedure precisely.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/Route53ZoneEnableDNSSECSigning.json)
- [AWS Route 53 DNSSEC documentation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html)
