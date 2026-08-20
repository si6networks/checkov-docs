# CKV_NCP_5: Ensure no access control groups allow inbound from 0.0.0.0:0 to port 3389
## Severity
**CRITICAL** (score: 9.0/10)

Allowing inbound access from 0.0.0.0/0 on port 3389 exposes RDP administrative access to the entire internet, a well-known high-value target for automated attacks and credential brute-forcing.

## Summary
This check fails any NCloud Access Control Group rule (`ncloud_access_control_group_rule`) that permits inbound RDP traffic on port 3389 from the entire internet (`0.0.0.0/0`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ncloud_access_control_group_rule`
- **Check type:** resource (subclass of the shared `AccessControlGroupInboundRule` base check, parameterized with `port=3389`)

## Why it matters
Port 3389 is the standard Windows Remote Desktop Protocol (RDP) port. RDP exposed to the entire internet is one of the highest-risk misconfigurations in cloud environments and a leading initial-access vector for ransomware campaigns: automated scanners constantly search for open port 3389, then attempt credential stuffing, brute force, or exploit known RDP vulnerabilities (e.g., BlueKeep-class flaws) to gain full interactive administrative access to the Windows host. Once compromised via RDP, attackers typically have direct GUI/administrative control, making lateral movement and ransomware deployment trivial. RDP access should always be restricted to specific trusted source IPs or tunneled through a VPN/bastion rather than exposed broadly.

## How Checkov evaluates this
This check is a subclass of the shared `AccessControlGroupInboundRule` base class, instantiated with `port=3389`. The shared logic inspects each inbound rule block of the `ncloud_access_control_group_rule` resource and fails when both conditions hold for a given rule:
- The source `ip_block` is `0.0.0.0/0` (or an equivalent unrestricted CIDR).
- The rule's port or port range includes port 3389.

If the source is scoped to a narrower range, or the rule's port range does not include 3389, the check passes.

## Non-compliant example
```hcl
resource "ncloud_access_control_group_rule" "rdp_inbound" {
  access_control_group_no = ncloud_access_control_group.windows_acg.id

  inbound {
    protocol    = "TCP"
    ip_block    = "0.0.0.0/0"
    port_range  = "3389"
    description = "Allow RDP from anywhere"
  }
}
```

## Remediated example
```hcl
resource "ncloud_access_control_group_rule" "rdp_inbound" {
  access_control_group_no = ncloud_access_control_group.windows_acg.id

  inbound {
    protocol    = "TCP"
    ip_block    = "203.0.113.4/32"  # corporate VPN egress IP only
    port_range  = "3389"
    description = "Allow RDP only from the corporate VPN egress IP"
  }
}
```

## Remediation steps
1. Restrict the inbound rule's `ip_block` to a small, known set of administrator IP ranges (VPN egress, jump host) instead of `0.0.0.0/0`.
2. Route RDP access through a bastion/jump host or NCP VPN gateway so port 3389 is never directly exposed to the public internet.
3. Enforce Network Level Authentication (NLA) and strong account lockout policies on the Windows host as defense in depth.
4. Consider RDP-over-VPN or a session-broker solution instead of direct RDP exposure entirely.
5. Re-run Checkov to confirm no rule still matches `0.0.0.0/0` on port 3389.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/AccessControlGroupInboundRulePort3389.py)
