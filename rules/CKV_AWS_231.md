# CKV_AWS_231: Ensure no NACL allow ingress from 0.0.0.0:0 to port 3389

## Severity
**CRITICAL** (score: 9.2/10)

Unrestricted 0.0.0.0/0 ingress to RDP (3389) at the subnet-wide NACL layer exposes every attached host to one of the most heavily exploited remote-administration ports, a documented initial-access vector for ransomware and brute-force compromise.

## Summary
This check ensures that no AWS Network ACL (NACL) rule allows unrestricted (`0.0.0.0/0`) inbound access to TCP port 3389 (RDP — Remote Desktop Protocol).

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_network_acl` (inline `ingress` blocks) and `aws_network_acl_rule` (standalone rule resources)

## Why it matters
Port 3389 is used by RDP for remote Windows administration. Exposing RDP to the entire internet is one of the most common and heavily exploited misconfigurations in cloud environments: it is a constant target for credential-stuffing and brute-force campaigns, and has been the initial access vector for numerous ransomware incidents (e.g. many high-profile ransomware families gain a foothold via internet-facing RDP with weak or reused credentials). Because a NACL operates at the subnet level and is stateless, an open rule here overrides the intended isolation of individual instances' security groups — every host in every subnet attached to that NACL becomes reachable on 3389 from any IP address, not just the specific bastion/jump host that may have been intended. This dramatically increases the exposed attack surface and is explicitly flagged by CIS AWS Foundations Benchmark controls (which call for RDP to never be open to 0.0.0.0/0).

## How Checkov evaluates this
This check subclasses the shared `AbsNACLUnrestrictedIngress` base check, parameterized with `port=3389`. It evaluates each ingress rule (inline `aws_network_acl.ingress` block or standalone `aws_network_acl_rule`) and looks for the combination of:
- `rule_action` = `"allow"`
- `egress` = `false`/absent
- `cidr_block`/`ipv6_cidr_block` = `0.0.0.0/0` or `::/0`
- `protocol` = TCP or `-1` (all protocols)
- port range (`from_port`–`to_port`) covering port 3389

If all of these hold simultaneously, the check **FAILS**. Restricting the CIDR, denying the rule, using a non-TCP protocol, or excluding port 3389 from the range causes the check to **PASS**.

## Non-compliant example
```hcl
resource "aws_network_acl" "app_subnet" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 3389
    to_port    = 3389
  }
}
```

## Remediated example
```hcl
resource "aws_network_acl" "app_subnet" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = "203.0.113.0/28"  # office/VPN egress range only
    from_port  = 3389
    to_port    = 3389
  }
}
```

## Remediation steps
1. Identify the flagged NACL rule permitting port 3389 from `0.0.0.0/0`.
2. Restrict `cidr_block`/`ipv6_cidr_block` to a specific, known set of source IPs (corporate VPN, bastion host CIDR, etc.).
3. Prefer eliminating direct RDP exposure entirely — use AWS Systems Manager Session Manager, a bastion host behind a VPN, or AWS Client VPN to reach Windows instances instead of opening RDP broadly.
4. Enforce MFA and strong password/account-lockout policies on any Windows host that still exposes RDP even on a restricted CIDR, as defense in depth.
5. Verify the corresponding security groups on affected instances also restrict port 3389, since NACL fixes alone do not guarantee instance-level protection.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NetworkACLUnrestrictedIngress3389.py)
- [AWS VPC Network ACLs documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
