# CKV_NCP_9: Ensure no NACL allow inbound from 0.0.0.0:0 to port 21
## Severity
**HIGH** (score: 7.5/10)

Allowing inbound access from 0.0.0.0/0 on port 21 (FTP control) exposes a legacy plaintext protocol's authentication and command channel to the entire internet, enabling credential interception and unauthorized access.

## Summary
This check fails any NCloud Network ACL rule (`ncloud_network_acl_rule`) that permits inbound traffic on port 21 (FTP control channel) from the entire internet (`0.0.0.0/0`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_network_acl_rule`
- **Check type:** resource (subclass of the shared `NACLInboundCheck` base check, parameterized with `port=21`)

## Why it matters
Port 21 is the FTP control channel, used to authenticate and issue commands to an FTP server. FTP transmits usernames and passwords in plaintext, so leaving port 21 reachable from the entire internet exposes any FTP service to credential interception, brute-force login attempts, and exploitation of known FTP server vulnerabilities. Because a Network ACL applies at the subnet level rather than to a single instance, an overly permissive rule here exposes every host in the subnet to internet-wide scanning for FTP services, magnifying the impact of what might have been intended as a narrow, single-host exception. As with port 20 (the FTP data channel), the recommended posture is to avoid plaintext FTP entirely in favor of SFTP/FTPS, and to never expose it broadly at the network ACL layer.

## How Checkov evaluates this
This check is a subclass of the shared `NACLInboundCheck` base class, instantiated with `port=21`. The shared logic inspects each inbound rule block of the `ncloud_network_acl_rule` resource and fails when both conditions hold for a given rule:
- The rule's action allows traffic (e.g., `ALLOW`) and its source `ip_block` is `0.0.0.0/0` (or an equivalent unrestricted CIDR).
- The rule's port or port range includes port 21.

If the rule denies traffic, restricts the source CIDR, or its port range does not include 21, the check passes.

## Non-compliant example
```hcl
resource "ncloud_network_acl_rule" "ftp_control_inbound" {
  network_acl_no = ncloud_network_acl.example.id

  inbound {
    priority    = 110
    protocol    = "TCP"
    rule_action = "ALLOW"
    ip_block    = "0.0.0.0/0"
    port_range  = "21"
  }
}
```

## Remediated example
```hcl
resource "ncloud_network_acl_rule" "ftp_control_inbound" {
  network_acl_no = ncloud_network_acl.example.id

  inbound {
    priority    = 110
    protocol    = "TCP"
    rule_action = "ALLOW"
    ip_block    = "10.0.5.0/24"  # restricted to a known internal management subnet
    port_range  = "21"
  }
}
```

## Remediation steps
1. Restrict the NACL rule's `ip_block` to a specific, known-necessary CIDR range instead of `0.0.0.0/0`.
2. Migrate off plaintext FTP to SFTP or FTPS wherever possible, eliminating the need to expose ports 20/21 at all.
3. If FTP must be retained, layer restrictions at both NACL and instance-level ACG, and require access via VPN or bastion rather than direct internet exposure.
4. Re-run Checkov to confirm no NACL rule still allows `0.0.0.0/0` on port 21.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/NACLInbound21.py)
