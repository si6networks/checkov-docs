# CKV_NCP_8: Ensure no NACL allow inbound from 0.0.0.0:0 to port 20
## Severity
**HIGH** (score: 7.5/10)

Allowing inbound access from 0.0.0.0/0 on port 20 (FTP data) exposes a legacy plaintext protocol to the entire internet, enabling credential and data interception.

## Summary
This check fails any NCloud Network ACL rule (`ncloud_network_acl_rule`) that permits inbound traffic on port 20 (FTP data channel) from the entire internet (`0.0.0.0/0`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ncloud_network_acl_rule`
- **Check type:** resource (subclass of the shared `NACLInboundCheck` base check, parameterized with `port=20`)

## Why it matters
Port 20 is used by the FTP protocol's data channel. FTP is an inherently insecure, unencrypted protocol — credentials, file listings, and file contents are all transmitted in plaintext, making them trivially interceptable by any network observer. Beyond the protocol weakness, a Network ACL is a subnet-wide control (unlike an instance-level security group), so leaving port 20 open at the NACL to `0.0.0.0/0` exposes every instance in the subnet to internet-wide scanning and potential exploitation of any FTP service running on it, and increases the blast radius of a single misconfiguration since it applies broadly rather than to one resource. Legacy FTP services should generally be replaced with secure alternatives (SFTP/FTPS) and, at minimum, never left open to the entire internet at the network layer.

## How Checkov evaluates this
This check is a subclass of the shared `NACLInboundCheck` base class, instantiated with `port=20`. The shared logic inspects each inbound rule block of the `ncloud_network_acl_rule` resource and fails when both conditions hold for a given rule:
- The rule's action allows traffic (e.g., `ALLOW`) and its source `ip_block` is `0.0.0.0/0` (or an equivalent unrestricted CIDR).
- The rule's port or port range includes port 20.

If the rule denies traffic, restricts the source CIDR, or its port range does not include 20, the check passes.

## Non-compliant example
```hcl
resource "ncloud_network_acl_rule" "ftp_data_inbound" {
  network_acl_no = ncloud_network_acl.example.id

  inbound {
    priority    = 100
    protocol    = "TCP"
    rule_action = "ALLOW"
    ip_block    = "0.0.0.0/0"
    port_range  = "20"
  }
}
```

## Remediated example
```hcl
resource "ncloud_network_acl_rule" "ftp_data_inbound" {
  network_acl_no = ncloud_network_acl.example.id

  inbound {
    priority    = 100
    protocol    = "TCP"
    rule_action = "ALLOW"
    ip_block    = "10.0.5.0/24"  # restricted to a known internal management subnet
    port_range  = "20"
  }
}
```

## Remediation steps
1. Restrict the NACL rule's `ip_block` to a specific, known-necessary CIDR range instead of `0.0.0.0/0`.
2. Replace legacy FTP with a secure alternative such as SFTP (SSH File Transfer Protocol, port 22) or FTPS, which provide encryption in transit.
3. If FTP must be retained for legacy compatibility, restrict access at both the NACL and instance-level ACG layers, and place the service behind a VPN or bastion.
4. Re-run Checkov to confirm no NACL rule still allows `0.0.0.0/0` on port 20.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/NACLInbound20.py)
