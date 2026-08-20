# CKV_ALI_2: Ensure no security groups allow ingress from 0.0.0.0:0 to port 22
## Severity
**CRITICAL** (score: 9.0/10)

A security group rule permitting unrestricted ingress from 0.0.0.0/0 to SSH (port 22) exposes a remote administrative interface to the entire internet, enabling brute-force and credential-stuffing attacks toward full host compromise.

## Summary
This check fails any Alibaba Cloud security group ingress rule that opens SSH (port 22) to the entire internet (`0.0.0.0/0`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `alicloud_security_group_rule` (only rules with `type = "ingress"` are evaluated; `egress` rules return `UNKNOWN`/not applicable)

## Why it matters
Port 22 is the standard SSH port used for administrative/shell access to Linux instances. Allowing ingress from `0.0.0.0/0` means any host on the internet can attempt to connect to SSH on the affected instances. In practice this exposes the instance to constant automated brute-force and credential-stuffing attacks, exploitation attempts against vulnerable SSH daemon versions, and — if any account has a weak or reused password or an improperly protected key — a direct path to full instance compromise. SSH access should be restricted to specific known IP ranges (corporate VPN, bastion host, CI runner) or delivered through a just-in-time access/bastion mechanism, never opened globally.

## How Checkov evaluates this
The check (`SecurityGroupUnrestrictedIngress22`, subclassing `AbsSecurityGroupUnrestrictedIngress` with `port=22`) inspects `alicloud_security_group_rule` resources:

1. If the resource has no `type` attribute, it's not a security group rule — PASS (not applicable).
2. If `type` is not `"ingress"` (i.e., it's `"egress"`), the result is `UNKNOWN` (this check only evaluates ingress rules).
3. If `port_range` is not set, PASS.
4. Otherwise it parses `port_range` (format `"<from>/<to>"`, e.g. `"22/22"`) into `from_port`/`to_port`.
5. If port 22 falls within `[from_port, to_port]` **and** `cidr_ip` contains `"0.0.0.0/0"` (or `cidr_ip` is empty/unset, which Alibaba Cloud treats as unrestricted), the rule FAILS.
6. Otherwise PASS.

## Non-compliant example
```hcl
resource "alicloud_security_group" "example" {
  name = "example-sg"
}

resource "alicloud_security_group_rule" "ssh_open" {
  type              = "ingress"
  ip_protocol       = "tcp"
  nic_type          = "intranet"
  policy            = "accept"
  port_range        = "22/22"
  priority          = 1
  security_group_id = alicloud_security_group.example.id
  cidr_ip           = "0.0.0.0/0"
}
```

## Remediated example
```hcl
resource "alicloud_security_group" "example" {
  name = "example-sg"
}

resource "alicloud_security_group_rule" "ssh_restricted" {
  type              = "ingress"
  ip_protocol       = "tcp"
  nic_type          = "intranet"
  policy            = "accept"
  port_range        = "22/22"
  priority          = 1
  security_group_id = alicloud_security_group.example.id
  # Restricted to a known corporate/VPN CIDR instead of the whole internet
  cidr_ip           = "203.0.113.0/24"
}
```

## Remediation steps
1. Identify every `alicloud_security_group_rule` with `type = "ingress"` whose `port_range` includes 22 and whose `cidr_ip` is `0.0.0.0/0` or blank.
2. Replace `cidr_ip` with the specific CIDR block(s) that legitimately need SSH access (office IP, VPN gateway, bastion host).
3. Where broad remote access is genuinely required, put a bastion host or Alibaba Cloud Bastionhost (Cloud SOC) in front of instances instead of opening SSH directly.
4. Consider disabling password-based SSH login entirely and using key-based auth plus Alibaba Cloud RAM/STS-based session managers.
5. Re-run `checkov` to confirm the rule now passes; no resource replacement is required — updating `cidr_ip` is an in-place change.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/SecurityGroupUnrestrictedIngress22.py)
- [Checkov base class source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/AbsSecurityGroupUnrestrictedIngress.py)
