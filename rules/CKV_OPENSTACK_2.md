# CKV_OPENSTACK_2: Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 (tcp / udp)
## Severity
**CRITICAL** (score: 9.1/10)

A security group allowing ingress from 0.0.0.0/0 on port 22 exposes SSH to the entire internet, making brute-force and credential-stuffing attacks against a remote administrative interface trivially reachable.

## Summary
This check flags OpenStack security group rules that allow unrestricted inbound access (`0.0.0.0/0`) to port 22 — the standard SSH port — over TCP or UDP.

## Applicability
**Checkov framework(s):** `terraform`

Terraform, resource types `openstack_compute_secgroup_v2` (legacy Nova security groups, using nested `rule` blocks) and `openstack_networking_secgroup_rule_v2` (Neutron security group rules).

## Why it matters
Port 22 is the default port for SSH, the primary remote-administration channel for Linux instances. A security group rule that permits ingress from `0.0.0.0/0` (i.e. any IPv4 address on the internet) to port 22 exposes SSH directly to:

- Automated internet-wide scanning and brute-force credential-stuffing campaigns, which continuously probe for open port 22 and attempt common/leaked credentials or weak keys.
- Exploitation of any unpatched OpenSSH vulnerability before the instance can be patched.
- A significantly expanded attack surface compared to restricting SSH to a bastion host, VPN, or known corporate IP ranges — turning a single misconfigured security group into the initial-access vector for the whole tenant/project.

Even with strong authentication (key-based only, MFA-fronted bastions), exposing the SSH listener itself to the whole internet is unnecessary risk; the accepted practice is to restrict management ports to specific trusted CIDR ranges or a bastion/jump host.

## How Checkov evaluates this
This check extends Checkov's shared `AbsSecurityGroupUnrestrictedIngress` base class, parameterized with `port=22`. For the supported OpenStack security-group resource types, it inspects the ingress rule definitions (`cidr`/`remote_ip_prefix`, `from_port`/`port_range_min`, `to_port`/`port_range_max`, and `protocol`/`ip_protocol`):

- **FAIL** if a rule's source CIDR is `0.0.0.0/0` (or an equivalent "any" representation) AND its protocol is `tcp` or `udp` AND its port range includes port 22.
- **PASS** if the rule restricts the source CIDR to a narrower range, uses a different protocol, or the port range excludes 22.
- Rules that don't define an ingress CIDR/port at all are not evaluated as a violation of this specific check.

## Non-compliant example
```hcl
resource "openstack_networking_secgroup_v2" "example" {
  name = "app-sg"
}

resource "openstack_networking_secgroup_rule_v2" "ssh_open" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"   # open to the entire internet
  security_group_id = openstack_networking_secgroup_v2.example.id
}
```

## Remediated example
```hcl
resource "openstack_networking_secgroup_v2" "example" {
  name = "app-sg"
}

resource "openstack_networking_secgroup_rule_v2" "ssh_restricted" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "10.0.0.0/24"   # restricted to a trusted management/VPN subnet
  security_group_id = openstack_networking_secgroup_v2.example.id
}
```

## Remediation steps
1. Identify every `openstack_networking_secgroup_rule_v2` / `openstack_compute_secgroup_v2` rule that allows ingress on port 22 from `0.0.0.0/0`.
2. Replace the broad CIDR with the specific ranges that legitimately need SSH access (office VPN egress IP, bastion host subnet, CI runner IP range).
3. Prefer routing SSH access through a bastion/jump host or a Session-Manager-style solution rather than exposing 22 on every instance's security group.
4. If broad access is genuinely required temporarily (e.g., troubleshooting), scope it narrowly and time-box it — do not leave `0.0.0.0/0` rules in committed Terraform.
5. Consider adding a Checkov custom policy or org guardrail to reject `0.0.0.0/0` in CI before merge.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/openstack/SecurityGroupUnrestrictedIngress22.py
- OpenStack Networking (Neutron) security group rule reference: https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/networking_secgroup_rule_v2
