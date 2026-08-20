# CKV_NCP_10: Ensure no NACL allow inbound from 0.0.0.0:0 to port 22

## Severity
**CRITICAL** (score: 9.5/10)

A Network ACL rule allowing inbound SSH (port 22) from 0.0.0.0/0 exposes a management/administrative interface at the subnet level to the entire internet, inviting brute-force and credential-stuffing attacks against every host behind it.

## Summary
This check ensures that Naver Cloud Platform (NCP) Network ACL rules (`ncloud_network_acl_rule`) do not permit unrestricted inbound access (from `0.0.0.0/0` or `::/0`) to TCP/UDP port 22 (SSH).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_network_acl_rule`
- **Check type:** resource-configuration check (Python, shared base class `NACLInboundCheck`)

## Why it matters
Port 22 is the standard SSH administration port. Allowing inbound SSH from any IP address on the internet (`0.0.0.0/0`) exposes every host behind that NACL to constant automated brute-force login attempts, credential-stuffing, and exploitation of any unpatched SSH-daemon vulnerabilities — all from anonymous, unauthenticated sources worldwide. Because a Network ACL sits at the subnet level (unlike a per-instance security group), a misconfigured rule here can expose an entire subnet's worth of hosts at once, not just a single instance. Restricting SSH ingress to known, trusted source ranges (a bastion host, VPN CIDR, or corporate IP range) removes an entire class of internet-facing attack surface for one of the most commonly targeted management ports.

## How Checkov evaluates this
This check (and its sibling `CKV_NCP_11` for RDP) share the `NACLInboundCheck` base class, parameterized with `port=22`. For each `inbound` rule in the `ncloud_network_acl_rule` resource:
1. It only examines rules where `rule_action == ["ALLOW"]`.
2. It reads the rule's `ip_block` (defaulting to `0.0.0.0/0` if unset).
3. If the source is `0.0.0.0/0` or `::/0`, it reads the `port_range`:
   - If `port_range` exactly equals `"22"`, the check **FAILS**.
   - If `port_range` is a range like `"20-25"`, it splits on `-` and **FAILS** if `22` falls within `[start, end]`.
4. If no matching ALLOW rule exposes port 22 to the world, the check **PASSES**.

## Non-compliant example
```hcl
resource "ncloud_network_acl_rule" "allow_ssh_all" {
  network_acl_no = ncloud_network_acl.main.id

  inbound {
    priority    = 100
    protocol    = "TCP"
    rule_action = "ALLOW"
    ip_block    = "0.0.0.0/0"
    port_range  = "22"
  }
}
```

## Remediated example
```hcl
resource "ncloud_network_acl_rule" "allow_ssh_bastion" {
  network_acl_no = ncloud_network_acl.main.id

  inbound {
    priority    = 100
    protocol    = "TCP"
    rule_action = "ALLOW"
    ip_block    = "203.0.113.10/32"  # restricted to bastion host / VPN egress IP
    port_range  = "22"
  }
}
```

## Remediation steps
1. Identify any `ncloud_network_acl_rule` inbound rule with `rule_action = "ALLOW"`, `ip_block = "0.0.0.0/0"` (or `::/0`), and a `port_range` covering port 22.
2. Replace the broad `ip_block` with a narrow, specific CIDR — e.g. a bastion host IP, corporate VPN egress range, or a dedicated jump-host subnet.
3. If broad SSH access is genuinely required for operational reasons, route it through a bastion/jump host or a VPN, and keep the NACL rule scoped to that bastion's address only.
4. Consider layering in security groups (`ncloud_access_control_group`) for defense in depth even after the NACL is restricted, since NACLs and ACGs are evaluated independently.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/NACLInbound22.py)
- [Naver Cloud Terraform provider: ncloud_network_acl_rule](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/network_acl_rule)
