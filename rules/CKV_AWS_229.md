# CKV_AWS_229: Ensure no NACL allow ingress from 0.0.0.0:0 to port 21

## Severity
**HIGH** (score: 7.3/10)

A NACL rule open to 0.0.0.0/0 on the FTP control port exposes every host in the subnet to a legacy, plaintext, credential-bearing protocol, with a blast radius spanning the whole subnet rather than a single instance.

## Summary
This check ensures that no AWS Network ACL (NACL) rule allows unrestricted (`0.0.0.0/0`) inbound access to TCP port 21 (FTP control port).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_network_acl` (inline `ingress` blocks) and `aws_network_acl_rule` (standalone rule resources)

## Why it matters
Port 21 is the FTP control channel. FTP is a legacy, plaintext protocol: credentials, commands, and (depending on mode) data can be transmitted unencrypted, making it trivial to intercept via network sniffing or man-in-the-middle attacks. Network ACLs are a stateless, subnet-level firewall layer in a VPC — if a NACL allows `0.0.0.0/0` on port 21, *any* host on the internet (or in a peered/adjacent network reachable to the subnet) can reach any instance in that subnet on port 21, regardless of the security groups attached to individual instances. Because NACLs apply to the entire subnet rather than a single ENI, a misconfigured rule here has a much broader blast radius than a single instance's security group mistake, and it is easy to overlook since NACLs are configured far less frequently than security groups. Exposing FTP externally is also a common vector for brute-force credential attacks and is explicitly called out in CIS AWS Foundations-style benchmarks as an unauthorized administrative/legacy port exposure.

## How Checkov evaluates this
This check subclasses the shared `AbsNACLUnrestrictedIngress` base check, parameterized with `port=21`. For each NACL rule (inline `ingress` block in `aws_network_acl`, or a standalone `aws_network_acl_rule`), it inspects:
- `rule_action` — must be `"allow"` for the rule to be considered (deny rules are not flagged).
- `egress` — must be `false`/absent (only ingress rules are evaluated).
- `cidr_block` / `ipv6_cidr_block` — must be the fully-open range (`0.0.0.0/0` or `::/0`).
- `protocol` — must be TCP (or `-1`/"all", which implicitly includes TCP).
- The rule's port range (`from_port`/`to_port`) — must include port 21.

If a rule matches all of the above (allow + ingress + wide-open CIDR + TCP + port range covering 21), the check **FAILS**. If the NACL/rule restricts the CIDR, denies the traffic, uses a different protocol that excludes TCP, or doesn't cover port 21, it **PASSES**.

## Non-compliant example
```hcl
resource "aws_network_acl" "public" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 21
    to_port    = 21
  }
}
```

## Remediated example
```hcl
resource "aws_network_acl" "public" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.0.0/16"  # restricted to internal CIDR only
    from_port  = 21
    to_port    = 21
  }
}
```

## Remediation steps
1. Identify the NACL rule(s) that allow port 21 from `0.0.0.0/0`.
2. Replace `0.0.0.0/0` with a specific, narrowly-scoped CIDR block (e.g. your corporate VPN range or internal VPC CIDR) if FTP access is genuinely required.
3. Preferably, eliminate FTP entirely and migrate to SFTP (port 22, via SSH) or FTPS/AWS Transfer Family, which provide encryption in transit.
4. If port 21 must remain open for legacy reasons, compensate with a `deny` NACL rule for `0.0.0.0/0` on port 21 at a lower rule number, and restrict via security groups as a second layer of defense.
5. Remember NACL rules are stateless — verify corresponding egress/ephemeral-port rules (1024-65535) are also correctly scoped so return traffic isn't inadvertently blocked or overly permissive.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NetworkACLUnrestrictedIngress21.py)
- [AWS VPC Network ACLs documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
