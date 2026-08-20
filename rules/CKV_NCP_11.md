# CKV_NCP_11: Ensure no NACL allow inbound from 0.0.0.0:0 to port 3389

## Severity
**CRITICAL** (score: 9.5/10)

A Network ACL rule allowing inbound RDP (port 3389) from 0.0.0.0/0 exposes a Windows administrative interface at the subnet level to unauthenticated internet-wide access, a classic and heavily targeted attack vector.

## Summary
This check ensures that Naver Cloud Platform (NCP) Network ACL rules (`ncloud_network_acl_rule`) do not permit unrestricted inbound access (from `0.0.0.0/0` or `::/0`) to TCP port 3389 (RDP).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_network_acl_rule`
- **Check type:** resource-configuration check (Python, shared base class `NACLInboundCheck`)

## Why it matters
Port 3389 is the standard Windows Remote Desktop Protocol (RDP) port. RDP endpoints exposed to the entire internet are a perennial top target for mass-scanning botnets, ransomware operators, and credential-stuffing tools — RDP brute-force is one of the most common initial-access vectors in ransomware incidents. Because a Network ACL applies at the subnet level, an overly broad rule here can silently expose every Windows host in a subnet to internet-wide RDP scanning, even if individual instance-level security groups look reasonably tight. Limiting RDP ingress to specific, trusted management IP ranges removes this direct exposure and forces remote administration through a controlled path (bastion/VPN) instead.

## How Checkov evaluates this
This check shares the `NACLInboundCheck` base class with `CKV_NCP_10`, parameterized with `port=3389`. For each `inbound` rule in the `ncloud_network_acl_rule` resource:
1. Only rules with `rule_action == ["ALLOW"]` are considered.
2. The rule's `ip_block` is read (defaulting to `0.0.0.0/0` if unset).
3. If the source is `0.0.0.0/0` or `::/0`, the `port_range` is examined:
   - An exact match of `"3389"` **FAILS** the check.
   - A range such as `"3300-3400"` **FAILS** if `3389` falls within `[start, end]`.
4. If no ALLOW rule exposes port 3389 to the world, the check **PASSES**.

## Non-compliant example
```hcl
resource "ncloud_network_acl_rule" "allow_rdp_all" {
  network_acl_no = ncloud_network_acl.main.id

  inbound {
    priority    = 110
    protocol    = "TCP"
    rule_action = "ALLOW"
    ip_block    = "0.0.0.0/0"
    port_range  = "3389"
  }
}
```

## Remediated example
```hcl
resource "ncloud_network_acl_rule" "allow_rdp_admins" {
  network_acl_no = ncloud_network_acl.main.id

  inbound {
    priority    = 110
    protocol    = "TCP"
    rule_action = "ALLOW"
    ip_block    = "198.51.100.0/28"  # corporate management VPN range only
    port_range  = "3389"
  }
}
```

## Remediation steps
1. Find any `ncloud_network_acl_rule` inbound rule with `rule_action = "ALLOW"`, source `0.0.0.0/0` (or `::/0`), and a `port_range` covering 3389.
2. Restrict `ip_block` to a narrow, known management CIDR (VPN egress, bastion IP, or corporate office range).
3. Where possible, avoid exposing RDP directly at all — front it with a bastion, VPN, or Naver Cloud's remote access tooling, and enforce MFA on the Windows accounts themselves.
4. Consider disabling RDP entirely on hosts that can be managed via other means (e.g. remote management APIs/agents), further shrinking the attack surface even for internally-scoped rules.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/NACLInbound3389.py)
- [Naver Cloud Terraform provider: ncloud_network_acl_rule](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/network_acl_rule)
