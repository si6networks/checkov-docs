# CKV_AWS_352: Ensure NACL ingress does not allow all Ports
## Severity
**HIGH** (score: 7.5/10)

A Network ACL rule that allows ingress on all ports removes subnet-level network segmentation, exposing every port on every instance in the subnet to whatever source the rule permits, a broad and easily overlooked network exposure.

## Summary
Checks that Network ACL ingress rules do not fail to specify a `from_port`, which the check treats as a proxy for a rule that isn't scoped to a specific port range.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework**: Terraform
- **Resource type**: `aws_network_acl_rule`

## Why it matters
Network ACLs are the stateless, subnet-level firewall layer in a VPC — evaluated for every packet in both directions, independent of Security Groups. An ingress NACL rule with no port restriction (i.e., effectively allowing all ports) combined with a broad CIDR (like `0.0.0.0/0`) exposes every listening service on every instance in the subnet to the source range, not just the intended one. Because NACLs are often used as an additional network-segmentation control (e.g., a stricter perimeter layer around Security Groups, or the only layer of defense for legacy/flat network designs), a rule that omits port scoping undermines defense-in-depth: even if Security Groups are later misconfigured or bypassed, an unrestricted NACL rule provides no compensating restriction, allowing lateral movement or external exposure of unintended services (databases, management ports, internal APIs) across the entire subnet.

## How Checkov evaluates this
This is a custom resource check on `aws_network_acl_rule`:
- If `egress` is set (truthy list with a truthy first element), the check returns **UNKNOWN** — this check only evaluates ingress rules; egress rules are out of scope for this specific check.
- Otherwise, it inspects `from_port`: if `from_port` is present and truthy (i.e., set to a specific value), the check **PASSES**.
- If `from_port` is absent or falsy (e.g., `0` or unset), the check **FAILS** — the rule is treated as unrestricted across ports.

Note: because Terraform's `aws_network_acl_rule` requires `from_port`/`to_port` for TCP/UDP protocols but they're irrelevant for protocol `"-1"` (all protocols) or ICMP, a rule using `protocol = "-1"` without ports set will still fail this check even though that may be the intended "allow all" design for a specific narrow use case — review context before assuming every failure is a true security gap, but treat any unscoped-port ingress rule with a broad CIDR as high risk.

## Non-compliant example
```hcl
resource "aws_network_acl_rule" "unrestricted_ingress" {
  network_acl_id = aws_network_acl.example.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  # from_port/to_port omitted -> all ports allowed
}
```

## Remediated example
```hcl
resource "aws_network_acl_rule" "restricted_ingress" {
  network_acl_id = aws_network_acl.example.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/16"   # scoped source too, where possible
  from_port      = 443
  to_port        = 443
}
```

## Remediation steps
1. Audit all `aws_network_acl_rule` resources with `egress = false` (or omitted, since `false` is the default) in your Terraform code.
2. Add explicit `from_port` and `to_port` values scoped to only the ports the subnet's workloads actually need to receive traffic on.
3. Tighten `cidr_block`/`ipv6_cidr_block` alongside the port scoping — port restriction and source restriction work together for real containment.
4. If a rule genuinely needs to allow all ports for a specific protocol (e.g., an internal management CIDR needing broad access), document the justification and consider scoping it to a narrow, trusted CIDR rather than `0.0.0.0/0`.
5. Remember NACL rules are stateless — you must add matching return-traffic rules (often via ephemeral port ranges 1024-65535) on the opposite direction, so tightening ingress ports requires verifying egress/return rules still function correctly.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NetworkACLUnrestricted.py
- AWS docs: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
