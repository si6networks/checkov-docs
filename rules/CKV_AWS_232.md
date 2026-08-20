# CKV_AWS_232: Ensure no NACL allow ingress from 0.0.0.0:0 to port 22

## Severity
**CRITICAL** (score: 9.2/10)

Unrestricted 0.0.0.0/0 ingress to SSH (22) at the subnet-wide NACL layer exposes every attached host to internet-wide brute-force and credential-stuffing attacks that commonly lead to full host takeover.

## Summary
This check ensures that no AWS Network ACL (NACL) rule allows unrestricted (`0.0.0.0/0`) inbound access to TCP port 22 (SSH).

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_network_acl` (inline `ingress` blocks) and `aws_network_acl_rule` (standalone rule resources)

## Why it matters
Port 22 is used for SSH, the primary remote-administration protocol for Linux hosts. Internet-facing SSH is a top target for automated brute-force and credential-stuffing bots that continuously scan the IPv4 space for open port 22. Because NACLs apply at the subnet boundary and are stateless, an unrestricted rule here bypasses the intended isolation that per-instance security groups provide — every instance in every subnet governed by that NACL becomes reachable on SSH from anywhere on the internet, regardless of how tightly individual security groups are scoped. This is a foundational control called out in essentially every cloud security benchmark (CIS AWS Foundations, PCI-DSS, NIST 800-53) precisely because SSH exposure is such a common and consequential misconfiguration — a compromised or weakly-configured SSH service can lead directly to full host takeover, lateral movement, and data exfiltration.

## How Checkov evaluates this
This check subclasses the shared `AbsNACLUnrestrictedIngress` base check, parameterized with `port=22`. It evaluates each ingress rule (inline `aws_network_acl.ingress` block or standalone `aws_network_acl_rule`) for the combination of:
- `rule_action` = `"allow"`
- `egress` = `false`/absent
- `cidr_block`/`ipv6_cidr_block` = `0.0.0.0/0` or `::/0`
- `protocol` = TCP or `-1` (all protocols)
- port range (`from_port`–`to_port`) covering port 22

If all conditions match simultaneously, the check **FAILS**. A restricted CIDR, a `deny` action, a non-TCP-inclusive protocol, or a port range that excludes 22 causes the check to **PASS**.

## Non-compliant example
```hcl
resource "aws_network_acl" "app_subnet" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol   = "tcp"
    rule_no    = 130
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 22
    to_port    = 22
  }
}
```

## Remediated example
```hcl
resource "aws_network_acl" "app_subnet" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol   = "tcp"
    rule_no    = 130
    action     = "allow"
    cidr_block = "10.20.0.0/16"  # internal management network only
    from_port  = 22
    to_port    = 22
  }
}
```

## Remediation steps
1. Identify the flagged NACL rule allowing port 22 from `0.0.0.0/0`.
2. Restrict `cidr_block`/`ipv6_cidr_block` to specific management/VPN/bastion source ranges.
3. Where possible, eliminate direct SSH exposure entirely by using AWS Systems Manager Session Manager (no open inbound port required) instead of routable SSH access.
4. If SSH must remain reachable, require key-based authentication only (disable password auth), and consider a bastion host or AWS Client VPN as the sole ingress point.
5. Verify the security groups attached to the affected instances also restrict SSH access — the NACL fix alone does not guarantee least-privilege at the instance layer, and both layers should agree.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NetworkACLUnrestrictedIngress22.py)
- [AWS VPC Network ACLs documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
