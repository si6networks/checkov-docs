# CKV_NCP_4: Ensure no access control groups allow inbound from 0.0.0.0:0 to port 22
## Severity
**CRITICAL** (score: 9.0/10)

Allowing inbound access from 0.0.0.0/0 on port 22 exposes SSH management access to the entire internet, a classic vector for brute-force and credential-stuffing compromise of the host.

## Summary
This check fails any NCloud Access Control Group rule (`ncloud_access_control_group_rule`) that permits inbound SSH traffic on port 22 from the entire internet (`0.0.0.0/0`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_access_control_group_rule`
- **Check type:** resource (subclass of the shared `AccessControlGroupInboundRule` base check, parameterized with `port=22`)

## Why it matters
Port 22 is the standard SSH port. Exposing SSH to the entire internet is one of the most common causes of cloud compromise: automated scanners continuously probe the internet for open port 22 and immediately begin credential brute-forcing and exploitation of known SSH vulnerabilities. Any weak password, reused key, or unpatched SSH daemon becomes an immediate foothold for an attacker to gain shell access to the instance, pivot deeper into the network, install malware/cryptominers, or use the host for further attacks. Administrative protocols like SSH should never be reachable from `0.0.0.0/0`; access should instead flow through a bastion host, VPN, or an allow-listed set of known administrator IP ranges.

## How Checkov evaluates this
This check is a subclass of the shared `AccessControlGroupInboundRule` base class, instantiated with `port=22`. The shared logic inspects each inbound rule block of the `ncloud_access_control_group_rule` resource and fails when both conditions hold for a given rule:
- The source `ip_block` is `0.0.0.0/0` (or an equivalent unrestricted CIDR).
- The rule's port or port range includes port 22.

If the source is scoped to a narrower range, or the rule's port range does not include 22, the check passes.

## Non-compliant example
```hcl
resource "ncloud_access_control_group_rule" "ssh_inbound" {
  access_control_group_no = ncloud_access_control_group.bastion_acg.id

  inbound {
    protocol    = "TCP"
    ip_block    = "0.0.0.0/0"
    port_range  = "22"
    description = "Allow SSH from anywhere"
  }
}
```

## Remediated example
```hcl
resource "ncloud_access_control_group_rule" "ssh_inbound" {
  access_control_group_no = ncloud_access_control_group.bastion_acg.id

  inbound {
    protocol    = "TCP"
    ip_block    = "203.0.113.4/32"  # corporate office / VPN egress IP only
    port_range  = "22"
    description = "Allow SSH only from the corporate VPN egress IP"
  }
}
```

## Remediation steps
1. Restrict the inbound rule's `ip_block` to specific, known administrator IP ranges (office network, VPN egress IP) instead of `0.0.0.0/0`.
2. Prefer routing all SSH access through a dedicated bastion host or NCP's session manager/VPN gateway, and only allow SSH from that bastion's IP on downstream instances' ACGs.
3. Enforce key-based authentication (disable password auth) on the SSH daemon itself as defense in depth, in addition to the network-level restriction.
4. Consider disabling direct SSH entirely in favor of a managed session-manager style access mechanism if the platform offers one.
5. Re-run Checkov to confirm no rule still matches `0.0.0.0/0` on port 22.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/AccessControlGroupInboundRulePort22.py)
