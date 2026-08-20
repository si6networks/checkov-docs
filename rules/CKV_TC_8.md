# CKV_TC_8: Ensure Tencent Cloud VPC security group rules do not accept all traffic

## Severity
**CRITICAL** (score: 8.5/10)

An ingress rule that accepts all traffic from 0.0.0.0/0 removes network-layer access control entirely, exposing whatever ports and services the resource runs to unauthenticated internet-wide scanning and exploitation.

## Summary
This check ensures that Tencent Cloud VPC security group ingress rules do not permit unrestricted traffic from any IPv4 (`0.0.0.0/0`) or IPv6 (`::/0`) source.

## Applicability
**Checkov framework(s):** `terraform`

Terraform, resource type `tencentcloud_security_group_rule_set` (Tencent Cloud provider), specifically its `ingress` blocks.

## Why it matters
A security group ingress rule that accepts all traffic (`0.0.0.0/0` or `::/0`) with an `ACCEPT` action removes any network-layer restriction on who can initiate connections to the protected resource, exposing every open port on the target to the entire internet. This is the single most common root cause of opportunistic cloud compromise: automated internet-wide scanners continuously probe for exactly this misconfiguration, and any port left open behind such a rule (databases, management interfaces, internal APIs never meant to be public) becomes immediately reachable by anyone, without needing to compromise any other layer of defense first. Least-privilege network design instead scopes ingress rules to specific known CIDR ranges (office IPs, VPN ranges, peer VPC subnets) or specific other security groups, so that only intended sources can even attempt a connection.

## How Checkov evaluates this
This is a `BaseResourceCheck` that iterates each `ingress` block of a `tencentcloud_security_group_rule_set`. For each ingress rule, it **FAILS** only when all of the following hold simultaneously:
1. The rule's `action` is `"ACCEPT"` (or unset — no `continue` skip occurs if absent since the check only skips when `action` is present and NOT `"ACCEPT"`), and
2. At least one of `cidr_block` or `ipv6_cidr_block` is set, and
3. `cidr_block`, if set, equals `"0.0.0.0/0"` (or `ipv6_cidr_block`, if set, equals `"::/0"` or `"0::0/0"`).

If a rule has no CIDR block set at all, or its CIDR is scoped narrower than the "all traffic" wildcard, or its action is something other than `ACCEPT` (e.g. `DROP`), that rule does not trigger a failure. The check **PASSES** if no ingress rule matches all the failing conditions above.

## Non-compliant example
```hcl
resource "tencentcloud_security_group_rule_set" "example" {
  security_group_id = tencentcloud_security_group.app_sg.id

  ingress {
    action     = "ACCEPT"
    cidr_block = "0.0.0.0/0"
    protocol   = "TCP"
    port       = "22"
  }
}
```

## Remediated example
```hcl
resource "tencentcloud_security_group_rule_set" "example" {
  security_group_id = tencentcloud_security_group.app_sg.id

  ingress {
    action     = "ACCEPT"
    cidr_block = "10.0.0.0/16"   # scoped to the internal VPN/VPC range, not 0.0.0.0/0
    protocol   = "TCP"
    port       = "22"
  }
}
```

## Remediation steps
1. Replace `cidr_block = "0.0.0.0/0"` (and `ipv6_cidr_block = "::/0"`) with specific, minimal CIDR ranges that reflect actual legitimate sources (office/VPN ranges, peer VPC CIDRs, specific known IPs).
2. Where the source is another Tencent Cloud resource rather than a fixed CIDR, reference it by security group rather than opening to all IPs.
3. For genuinely public-facing services (e.g. a web server on 80/443), scope the rule to only the necessary ports rather than leaving other ports open on the same wildcard rule, and consider fronting with a CLB/WAF instead of exposing the instance directly.
4. Review existing security groups for other overly broad rules beyond what this check flags (e.g. wide port ranges combined with narrower CIDRs) as part of a broader network hardening pass.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/VPCSecurityGroupRuleSet.py
