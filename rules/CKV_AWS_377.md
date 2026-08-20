# CKV_AWS_377: Ensure Route 53 domains have transfer lock protection

## Severity
**LOW** (score: 2.0/10)

Lacking Route 53 domain transfer lock enables unauthorized or fraudulent domain transfers away from the account, which can eventually lead to full domain hijacking, but exploitation requires additional registrar-level access or social engineering.

## Summary
This check ensures a Route 53 registered domain has the registry `transfer_lock` protection enabled to prevent unauthorized transfer of the domain to another registrar.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_route53domains_registered_domain`

## Why it matters
Domain transfer lock (also called "registrar lock" or `clientTransferProhibited` at the registry level) prevents a domain from being transferred to a different registrar without first being unlocked. Without it:

- An attacker who gains any foothold in the account or convinces a registrar via social engineering / stolen credentials can initiate an unauthorized domain transfer, effectively hijacking the domain entirely (moving it out of AWS's control).
- Domain hijacking is a severe, hard-to-reverse incident: it can be used to redirect a company's entire web/email/API traffic to attacker-controlled infrastructure, issue fraudulent TLS certificates via domain validation, or hold the domain for ransom.
- Recovery from a hijacked domain transfer can take weeks and often requires ICANN dispute resolution.

Enabling transfer lock is one of the cheapest, highest-leverage defenses against this class of attack.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` inspecting the `transfer_lock` attribute. The forbidden value is `False` — if `transfer_lock` is explicitly set to `false`, the check **FAILS**. If it is `true`, or the attribute is simply absent from the configuration (letting Route53Domains' own default apply, which is typically locked), the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_route53domains_registered_domain" "example" {
  domain_name = "example.com"

  transfer_lock = false

  name_server {
    name = "ns-1.awsdns-01.com"
  }
  name_server {
    name = "ns-2.awsdns-02.net"
  }
}
```

## Remediated example
```hcl
resource "aws_route53domains_registered_domain" "example" {
  domain_name = "example.com"

  transfer_lock = true

  name_server {
    name = "ns-1.awsdns-01.com"
  }
  name_server {
    name = "ns-2.awsdns-02.net"
  }
}
```

## Remediation steps
1. Set `transfer_lock = true` explicitly on the `aws_route53domains_registered_domain` resource (or simply omit the attribute so the registrar default lock applies, then verify it via the console/CLI).
2. If you have a legitimate, planned domain transfer in progress, temporarily disable the lock only for the duration of the transfer and re-enable it immediately afterward.
3. Combine this with MFA on the AWS account/root user and least-privilege IAM policies restricting who can call `route53domains:DisableDomainTransferLock` or modify this resource.
4. This is a metadata-only change and does not require resource replacement or downtime.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/Route53TransferLock.py)
- [AWS Route 53 domain transfer lock documentation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer-to-another-registrar.html)
