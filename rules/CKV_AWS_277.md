# CKV_AWS_277: Ensure no security groups allow ingress from 0.0.0.0:0 to port -1
## Severity
**CRITICAL** (score: 9.8/10)

A security group rule allowing ingress from 0.0.0.0/0 on all protocols/ports (-1) exposes every port on the attached resources directly to the entire internet, effectively removing network-layer access control.

## Summary
This check fails when a security group (or security group rule) allows inbound traffic from any IPv4/IPv6 address (`0.0.0.0/0` or `::/0`) across **all ports and protocols** (port range represented as `-1`, i.e. "any port").

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resources:** `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`

## Why it matters
A security group ingress rule with `-1` port range and `0.0.0.0/0` as the source is effectively "allow anyone on the internet to reach any port on this instance/ENI." This is the most permissive network posture possible short of disabling the security group entirely: it exposes every service listening on the resource — including ones that were never intended to be internet-facing (databases, management interfaces, internal RPC, SSH, RDP) — to unauthenticated scanning and exploitation from the entire internet. Attackers routinely scan `0.0.0.0/0` allow-all rules to find exposed services, and a single misconfigured "all ports" rule can undo careful per-port hardening elsewhere. This differs from (and is strictly worse than) opening a single known port to the internet, because it removes the defense-in-depth benefit of least-privilege network segmentation entirely.

## How Checkov evaluates this
This check subclasses `AbsSecurityGroupUnrestrictedIngress` with `port=-1`. For each ingress rule (whether embedded in `aws_security_group`, a standalone `aws_security_group_rule` of `type = "ingress"`, or `aws_vpc_security_group_ingress_rule`) it computes whether the rule's port range contains port `-1`, treating `from_port == 0 and to_port == 0` as "expand to 0-65535", and also matching when `protocol == "-1"` with `from_port == 0` and `to_port == 65535` (the Terraform convention for "all protocols/ports"). If that condition holds AND the rule's source is `0.0.0.0/0` in `cidr_blocks`/`cidr_ipv4`, or `::/0` (or the expanded all-zeros form) in `ipv6_cidr_blocks`/`cidr_ipv6`, or the rule has no CIDR/security-group reference at all, the check **fails**. A rule referencing `self = true`, a `security_groups` set, `source_security_group_id`, or a `prefix_list_ids` value passes. Egress-typed `aws_security_group_rule` resources return `UNKNOWN` (not evaluated by this check).

## Non-compliant example
```hcl
resource "aws_security_group" "bad" {
  name   = "wide-open"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

## Remediated example
```hcl
resource "aws_security_group" "good" {
  name   = "scoped-access"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"] # restricted to internal VPC CIDR, not 0.0.0.0/0
  }
}
```

## Remediation steps
1. Replace `protocol = "-1"` (all protocols/ports) ingress rules with explicit rules that open only the specific port(s) each service actually needs.
2. Restrict the source CIDR to known ranges (VPN CIDR, VPC CIDR, specific corporate IP ranges) instead of `0.0.0.0/0`/`::/0`.
3. Where possible, reference a source security group (`security_groups` / `source_security_group_id`) instead of a CIDR block, so access is scoped to specific resources rather than any IP.
4. For legitimately public services (e.g., a public HTTPS load balancer), open only the required port (443) to `0.0.0.0/0`, never `-1`/all ports.
5. Put truly internet-facing management access behind a bastion host, SSM Session Manager, or VPN rather than a broad security group rule.
6. Re-run `terraform plan` after tightening rules to confirm no dependent resources assumed the wide-open access.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SecurityGroupUnrestrictedIngressAny.py
- AWS docs: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html
