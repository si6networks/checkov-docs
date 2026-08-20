# CKV_AWS_382: Ensure no security groups allow egress from 0.0.0.0:0 to port -1

## Severity
**LOW** (score: 2.0/10)

Unrestricted egress to any port from a security group allows compromised instances to exfiltrate data or communicate with attacker-controlled infrastructure without restriction, though it requires a prior compromise to be exploited.

## Summary
This check ensures no security group rule allows unrestricted outbound (egress) traffic to `0.0.0.0/0` covering all ports/protocols (`port -1`, i.e., "all traffic").

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_security_group` (inline `egress` blocks), `aws_security_group_rule`, `aws_vpc_security_group_egress_rule`

## Why it matters
A security group egress rule of `0.0.0.0/0` on all protocols/ports (`from_port = 0`, `to_port = 0`, `protocol = "-1"`) removes all outbound network filtering for the resources attached to that security group. This matters because:

- If an instance/container/Lambda in that security group is ever compromised (via a vulnerable dependency, exposed service, or supply-chain attack), unrestricted egress lets the attacker exfiltrate data to any external destination and freely establish command-and-control (C2) channels back to attacker infrastructure without any network-layer restriction.
- It also permits lateral movement to unintended internal ranges and makes it trivial for compromised workloads to reach out to arbitrary internet endpoints for malware download, cryptomining pools, or further attack staging.
- Restricting egress is a foundational defense-in-depth control recommended by CIS AWS Foundations Benchmark and most cloud security baselines — many environments default to allowing all egress, but that default is exactly what this check flags as needing tightening.

## How Checkov evaluates this
This check (`SecurityGroupUnrestrictedEgressAll`) is built on the shared `AbsSecurityGroupUnrestrictedEgress` base class, parameterized with `port=-1` to represent "all ports/protocols." It inspects `egress` blocks (or the equivalent standalone `aws_security_group_rule`/`aws_vpc_security_group_egress_rule` resources) for:
- A `cidr_blocks` (or `ipv6_cidr_blocks`) entry of `0.0.0.0/0` (or `::/0`), **and**
- A protocol/port range that spans "all" (typically `protocol = "-1"`, which implies all ports).

If such a rule is found, the check **FAILS**; otherwise it **PASSES**. This is distinct from more granular per-port egress checks — this one specifically targets the "all traffic, from anywhere" catch-all rule.

## Non-compliant example
```hcl
resource "aws_security_group" "example" {
  name   = "example-sg"
  vpc_id = aws_vpc.example.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

## Remediated example
```hcl
resource "aws_security_group" "example" {
  name   = "example-sg"
  vpc_id = aws_vpc.example.id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to package repositories / APIs"
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [aws_vpc.example.cidr_block]
    description = "DNS within VPC"
  }
}
```

## Remediation steps
1. Replace the single `protocol = "-1"` / `0.0.0.0/0` egress rule with specific rules scoped to the exact ports/protocols the workload actually needs (e.g., 443 for HTTPS, 53 for DNS, a specific database port to a specific internal CIDR).
2. Where the destination is known (e.g., an internal service, a VPC endpoint, an RDS instance), scope `cidr_blocks` to that specific CIDR or reference a peer security group instead of `0.0.0.0/0`.
3. For outbound internet access still required broadly (e.g., package downloads over HTTPS), it is acceptable to allow `0.0.0.0/0` scoped to port 443 only — the point is to eliminate "all ports" exposure, not necessarily to eliminate all internet egress.
4. Use VPC endpoints (Gateway/Interface) for AWS service traffic (S3, DynamoDB, ECR, etc.) so that traffic never needs to leave the VPC via a public egress rule at all.
5. This change applies in place to the security group; no resource replacement needed, but audit dependent workloads first to avoid breaking connectivity when tightening egress.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SecurityGroupUnrestrictedEgressAny.py)
- [AWS Security group rules documentation](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
