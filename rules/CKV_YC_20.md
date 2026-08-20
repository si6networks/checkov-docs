# CKV_YC_20: Ensure security group rule is not allow-all

## Severity
**CRITICAL** (score: 9.4/10)

An individual security group rule permitting all ports/protocols from 0.0.0.0/0 on ingress is a direct, unauthenticated internet-wide exposure of whatever resource the rule applies to.

## Summary
This check fails when a standalone Yandex VPC security group *rule* (`yandex_vpc_security_group_rule`) is an ingress rule allowing all ports from the entire internet (`0.0.0.0/0`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `yandex_vpc_security_group_rule`

## Why it matters
This check applies the same logic as CKV_YC_19 but to the standalone `yandex_vpc_security_group_rule` resource, which lets you define security group rules independently of the parent `yandex_vpc_security_group` block. An ingress rule with direction `ingress`, source `0.0.0.0/0`, and no effective port restriction (all ports, or no restriction at all) exposes every port of anything protected by that security group to unauthenticated network access from any host on the internet. This removes network-layer isolation entirely, exposing management interfaces, databases, and internal services that were never meant to be internet-facing, and providing attackers with a much larger set of entry points to probe (any listening service on any port becomes reachable, not just the intended application port).

## How Checkov evaluates this
The check (`VPCSecurityGroupRuleAllowAll`) is a custom `BaseResourceCheck` (`scan_resource_conf`):
- Only rules where `direction == "ingress"` are evaluated (egress rules are exempt).
- It reads `v4_cidr_blocks` and iterates the CIDR list.
- If `0.0.0.0/0` is present:
  - If a `port` attribute is present and equals `-1`, the check **FAILS**.
  - If `port` is present with any other value, it **PASSES**.
  - If neither `from_port` nor `to_port` is set (and no `port`), the check **FAILS**.
  - If `from_port == 0` and `to_port == 65535` (full port range), the check **FAILS**.
- Otherwise (non-ingress direction, no `0.0.0.0/0` CIDR, or a scoped port range), the check **PASSES**.

## Non-compliant example
```hcl
resource "yandex_vpc_security_group_rule" "open_all" {
  security_group_binding = yandex_vpc_security_group.example.id
  direction               = "ingress"
  protocol                = "ANY"
  port                    = -1
  v4_cidr_blocks          = ["0.0.0.0/0"]  # all ports from anywhere -- FAILS CKV_YC_20
}
```

## Remediated example
```hcl
resource "yandex_vpc_security_group_rule" "https_only" {
  security_group_binding = yandex_vpc_security_group.example.id
  direction               = "ingress"
  protocol                = "TCP"
  port                    = 443
  v4_cidr_blocks          = ["0.0.0.0/0"]  # single port only -- PASSES CKV_YC_20
}
```

## Remediation steps
1. Remove the `port = -1` / unrestricted from-to port range combined with `v4_cidr_blocks = ["0.0.0.0/0"]`.
2. Explicitly set `port` (or a tight `from_port`/`to_port` range) to only the ports the associated service actually requires.
3. Restrict `v4_cidr_blocks` to known, necessary source ranges instead of the full internet wherever the traffic doesn't genuinely need to be public.
4. Never allow-all for administrative ports (SSH, RDP, database ports); use bastion hosts or VPN-restricted CIDRs for those.
5. Since this is a standalone rule resource (as opposed to an inline `ingress` block on the security group itself, covered by CKV_YC_19), audit both resource types across your codebase — they are evaluated by separate checks and can be defined independently, so fixing one does not guarantee the other is compliant.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/VPCSecurityGroupRuleAllowAll.py)
- [Yandex Cloud VPC security groups documentation](https://yandex.cloud/en/docs/vpc/concepts/security-groups)
