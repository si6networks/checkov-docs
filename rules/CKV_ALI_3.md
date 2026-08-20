# CKV_ALI_3: Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389
## Severity
**CRITICAL** (score: 9.0/10)

A security group rule permitting unrestricted ingress from 0.0.0.0/0 to RDP (port 3389) exposes a remote administrative interface to the entire internet, enabling brute-force and credential-stuffing attacks toward full host compromise.

## Summary
This check fails any Alibaba Cloud security group ingress rule that opens RDP (port 3389) to the entire internet (`0.0.0.0/0`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `alicloud_security_group_rule` (only rules with `type = "ingress"` are evaluated; `egress` rules return `UNKNOWN`)

## Why it matters
Port 3389 is the standard RDP port used for remote administrative access to Windows instances. Exposing it to `0.0.0.0/0` puts the instance directly in the path of internet-wide RDP scanning, brute-force login attempts, and exploitation of known RDP vulnerabilities (e.g. BlueKeep-class flaws that allow pre-auth remote code execution). RDP exposure is one of the most common initial-access vectors used by ransomware operators to gain a foothold in cloud environments. Access should be limited to specific trusted networks or brokered through a bastion/jump host rather than opened globally.

## How Checkov evaluates this
The check (`SecurityGroupUnrestrictedIngress3389`, subclassing `AbsSecurityGroupUnrestrictedIngress` with `port=3389`) inspects `alicloud_security_group_rule` resources:

1. If the resource has no `type` attribute, it's not a security group rule — PASS.
2. If `type` is not `"ingress"`, the result is `UNKNOWN`.
3. If `port_range` is not set, PASS.
4. Otherwise parses `port_range` (e.g. `"3389/3389"`) into `from_port`/`to_port`.
5. If port 3389 falls within `[from_port, to_port]` **and** `cidr_ip` contains `"0.0.0.0/0"` (or is empty), the rule FAILS.
6. Otherwise PASS.

## Non-compliant example
```hcl
resource "alicloud_security_group" "example" {
  name = "example-sg"
}

resource "alicloud_security_group_rule" "rdp_open" {
  type              = "ingress"
  ip_protocol       = "tcp"
  nic_type          = "intranet"
  policy            = "accept"
  port_range        = "3389/3389"
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

resource "alicloud_security_group_rule" "rdp_restricted" {
  type              = "ingress"
  ip_protocol       = "tcp"
  nic_type          = "intranet"
  policy            = "accept"
  port_range        = "3389/3389"
  priority          = 1
  security_group_id = alicloud_security_group.example.id
  # Restricted to a known corporate/VPN CIDR instead of the whole internet
  cidr_ip           = "203.0.113.0/24"
}
```

## Remediation steps
1. Identify every `alicloud_security_group_rule` with `type = "ingress"` whose `port_range` includes 3389 and whose `cidr_ip` is `0.0.0.0/0` or blank.
2. Scope `cidr_ip` down to the specific ranges that need RDP (office network, VPN, bastion host IP).
3. Prefer routing RDP through a bastion host / Alibaba Cloud Bastionhost rather than exposing it directly on instances.
4. Enable Network Level Authentication (NLA) and enforce MFA for any account permitted to RDP in.
5. Re-run `checkov` to confirm the rule now passes; this is an in-place `cidr_ip` change, no resource replacement needed.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/SecurityGroupUnrestrictedIngress3389.py)
- [Checkov base class source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/AbsSecurityGroupUnrestrictedIngress.py)
