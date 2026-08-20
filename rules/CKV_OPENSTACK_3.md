# CKV_OPENSTACK_3: Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 (tcp / udp)
## Severity
**CRITICAL** (score: 9.1/10)

A security group allowing ingress from 0.0.0.0/0 on port 3389 exposes RDP, a frequently targeted remote administrative protocol, to the public internet, enabling brute-force and known-exploit attacks against instances.

## Summary
This check flags OpenStack security group rules that allow unrestricted inbound access (`0.0.0.0/0`) to port 3389 — the standard RDP (Remote Desktop Protocol) port — over TCP or UDP.

## Applicability
**Checkov framework(s):** `terraform`

Terraform, resource types `openstack_compute_secgroup_v2` (legacy Nova security groups) and `openstack_networking_secgroup_rule_v2` (Neutron security group rules).

## Why it matters
Port 3389 is the default port for Windows Remote Desktop Protocol, the primary remote-administration channel for Windows instances. Exposing it to `0.0.0.0/0` means:

- RDP is one of the most heavily targeted services on the internet for brute-force and credential-stuffing attacks, and has historically been the delivery vector for major ransomware campaigns (e.g., exploitation via weak/reused credentials or unpatched RDP vulnerabilities such as BlueKeep, CVE-2019-0708).
- Any unpatched RDP service vulnerability becomes immediately reachable by any internet host, not just legitimate administrators.
- Successful compromise of an exposed RDP endpoint typically grants an attacker an interactive desktop session with the privileges of the compromised account, often a direct path to full host takeover and lateral movement within the tenant network.

As with SSH, the safe pattern is to keep RDP off the public internet entirely and route administrative access through a bastion/jump host, VPN, or a broker service, restricting security group ingress to specific known CIDR ranges.

## How Checkov evaluates this
This check extends the shared `AbsSecurityGroupUnrestrictedIngress` base class, parameterized with `port=3389`. For the supported OpenStack security-group resource types, it inspects ingress rule CIDR, protocol, and port range:

- **FAIL** if a rule's source CIDR is `0.0.0.0/0` (or equivalent) AND its protocol is `tcp` or `udp` AND its port range includes port 3389.
- **PASS** if the CIDR is restricted, the protocol differs, or the port range excludes 3389.

## Non-compliant example
```hcl
resource "openstack_networking_secgroup_v2" "example" {
  name = "windows-sg"
}

resource "openstack_networking_secgroup_rule_v2" "rdp_open" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 3389
  port_range_max    = 3389
  remote_ip_prefix  = "0.0.0.0/0"   # RDP open to the entire internet
  security_group_id = openstack_networking_secgroup_v2.example.id
}
```

## Remediated example
```hcl
resource "openstack_networking_secgroup_v2" "example" {
  name = "windows-sg"
}

resource "openstack_networking_secgroup_rule_v2" "rdp_restricted" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 3389
  port_range_max    = 3389
  remote_ip_prefix  = "10.0.0.0/24"   # restricted to trusted management subnet/VPN
  security_group_id = openstack_networking_secgroup_v2.example.id
}
```

## Remediation steps
1. Locate every OpenStack security group rule permitting ingress on port 3389 from `0.0.0.0/0`.
2. Restrict `remote_ip_prefix`/CIDR to only the specific management network, VPN range, or bastion host subnet that needs RDP access.
3. Prefer disabling direct RDP exposure entirely and routing through a bastion host or a remote-access broker/VPN.
4. Ensure any Windows instances relying on RDP also enforce Network Level Authentication (NLA) and strong account lockout policies as defense in depth.
5. Audit existing deployed security groups (not just Terraform source) since drift can reintroduce an open rule outside of code.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/openstack/SecurityGroupUnrestrictedIngress3389.py
- OpenStack Networking (Neutron) security group rule reference: https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/networking_secgroup_rule_v2
