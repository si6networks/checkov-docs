# CKV_AWS_344: Ensure that Network firewalls have deletion protection enabled
## Severity
**HIGH** (score: 7.5/10)

Without deletion protection, an AWS Network Firewall instance can be accidentally or maliciously deleted, removing inline traffic filtering and leaving protected subnets unfiltered until it is recreated.

## Summary
Requires AWS Network Firewall `aws_networkfirewall_firewall` resources to set `delete_protection = true`, preventing accidental or unauthorized deletion of the firewall.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework**: Terraform
- **Resource type**: `aws_networkfirewall_firewall`

## Why it matters
An AWS Network Firewall typically enforces perimeter security controls (stateful/stateless traffic filtering, domain filtering, IDS/IPS-style rules) for a VPC. If the firewall resource can be deleted without protection, a single mistaken `terraform destroy`, a misapplied Terraform plan, a compromised CI/CD pipeline, or an over-privileged IAM principal issuing `DeleteFirewall` could remove network-layer protections entirely — silently opening previously blocked traffic paths (e.g. egress to malicious C2 domains, unrestricted lateral movement) with no error or warning at the infrastructure layer. Because firewall deletion is often a "fire and forget" high-impact action with no compensating control, deletion protection acts as a required, deliberate safeguard analogous to RDS/S3 deletion protection — forcing an explicit two-step action (disable protection, then delete) before the control plane will honor a delete request.

## How Checkov evaluates this
This is a Terraform resource value check that inspects `delete_protection`:
- **PASS**: `delete_protection = true`.
- **FAIL**: `delete_protection = false`, or the `delete_protection` attribute/block is missing entirely (`missing_block_result=CheckResult.FAILED` — unlike many similar checks, an absent attribute here counts as a failure, not a pass, because the AWS default for this field is `false`).

## Non-compliant example
```hcl
resource "aws_networkfirewall_firewall" "example" {
  name                = "example-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.example.arn
  vpc_id              = aws_vpc.example.id

  subnet_mapping {
    subnet_id = aws_subnet.firewall.id
  }
  # delete_protection not set -> defaults to false -> FAILS
}
```

## Remediated example
```hcl
resource "aws_networkfirewall_firewall" "example" {
  name                = "example-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.example.arn
  vpc_id              = aws_vpc.example.id
  delete_protection   = true   # blocks accidental/unauthorized deletion

  subnet_mapping {
    subnet_id = aws_subnet.firewall.id
  }
}
```

## Remediation steps
1. Find every `aws_networkfirewall_firewall` resource in your Terraform code.
2. Add `delete_protection = true`.
3. If you genuinely need to delete or replace the firewall later (e.g. during a planned migration), you must first set `delete_protection = false` and apply that change before Terraform/AWS will allow the delete — plan for this as a two-step operation.
4. This attribute is a simple in-place update; it does not require resource replacement.
5. Combine with `subnet_change_protection` and `firewall_policy_change_protection` (related but separate settings) if you also want to guard against unintended subnet or policy attachment changes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NetworkFirewallDeletionProtection.py
- AWS docs: https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-deletion-protection.html
