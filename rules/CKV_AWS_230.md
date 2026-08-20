# CKV_AWS_230: Ensure no NACL allow ingress from 0.0.0.0:0 to port 20

## Severity
**HIGH** (score: 7.2/10)

A NACL rule open to 0.0.0.0/0 on the FTP data port exposes an entire subnet's hosts to unencrypted file-transfer traffic that can be intercepted or abused for exfiltration.

## Summary
This check ensures that no AWS Network ACL (NACL) rule allows unrestricted (`0.0.0.0/0`) inbound access to TCP port 20 (FTP data port).

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_network_acl` (inline `ingress` blocks) and `aws_network_acl_rule` (standalone rule resources)

## Why it matters
Port 20 is the FTP data channel, used alongside port 21 (control channel) for active-mode FTP file transfers. Like the control channel, FTP data transfer is unencrypted, so file contents and any credentials embedded in the session can be captured by network eavesdroppers. NACLs operate at the subnet boundary and are stateless, meaning an open rule here applies to every instance in every subnet the NACL is attached to — not just one host — so a single misconfigured rule can expose an entire application tier to inbound connections on the FTP data port from anywhere on the internet. Attackers scanning for open FTP data ports can use them to pull or push files, pivot into internal networks, or combine with other misconfigurations (e.g. an anonymous-FTP-enabled server) to exfiltrate data. Because organizations rarely intend to expose legacy FTP externally, an open 0.0.0.0/0 rule on port 20 is almost always leftover cruft or a copy-paste error rather than an intentional design choice.

## How Checkov evaluates this
This check subclasses the shared `AbsNACLUnrestrictedIngress` base check, parameterized with `port=20`. It inspects each ingress rule (inline in `aws_network_acl` or standalone `aws_network_acl_rule`) for the combination of:
- `rule_action` = `"allow"`
- `egress` = `false`/absent (ingress only)
- `cidr_block`/`ipv6_cidr_block` = fully open (`0.0.0.0/0` or `::/0`)
- `protocol` = TCP or `-1` (all protocols)
- port range (`from_port`–`to_port`) covering port 20

If all conditions hold, the check **FAILS**. Any rule that denies the traffic, restricts the CIDR, uses a non-TCP-inclusive protocol, or excludes port 20 from its range **PASSES**.

## Non-compliant example
```hcl
resource "aws_network_acl_rule" "ftp_data" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 20
  to_port        = 20
}
```

## Remediated example
```hcl
resource "aws_network_acl_rule" "ftp_data" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.1.0/24"  # restricted to a specific internal range
  from_port      = 20
  to_port        = 20
}
```

## Remediation steps
1. Locate the flagged NACL rule allowing port 20 from `0.0.0.0/0`.
2. Narrow the `cidr_block`/`ipv6_cidr_block` to only the specific source ranges that legitimately need FTP data access.
3. Migrate off active-mode/plaintext FTP where possible — use SFTP or AWS Transfer Family with TLS/SSH instead, eliminating the need for this port entirely.
4. If FTP must remain, ensure a corresponding restrictive security group is also in place on the instances, since NACLs alone should not be the only control.
5. Double check the paired egress/ephemeral port rules on the NACL, since stateless NACLs require explicit rules for return traffic on both directions.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NetworkACLUnrestrictedIngress20.py)
- [AWS VPC Network ACLs documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
