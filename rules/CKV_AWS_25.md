# CKV_AWS_25: Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389

## Severity
**CRITICAL** (score: 9.5/10)

Exposing RDP (port 3389) to 0.0.0.0/0 opens a top brute-force and exploit target (e.g. BlueKeep) directly to the entire internet, a leading initial-access vector in ransomware intrusions.

## Summary
This check ensures that no security group (or security group rule) permits unrestricted inbound access (`0.0.0.0/0` or `::/0`) to TCP port 3389, the Windows Remote Desktop Protocol (RDP) port.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Frameworks:** CloudFormation, Terraform
- **Resource types:**
  - CloudFormation: `AWS::EC2::SecurityGroup`, `AWS::EC2::SecurityGroupIngress`
  - Terraform: `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`

## Why it matters
RDP (port 3389) is one of the most heavily targeted ports on the internet for brute-force credential attacks and exploitation of Windows vulnerabilities (e.g., BlueKeep/CVE-2019-0708, various RDP-based ransomware entry vectors like the widespread use of exposed RDP by ransomware operators to gain initial access). Exposing RDP to `0.0.0.0/0` means literally any host on the internet can attempt to authenticate against your Windows instance, and a single weak or reused password, or an unpatched RDP service, becomes a direct path to full instance compromise. This is consistently one of the top initial-access vectors observed in ransomware incident response reports, and cloud providers' own security guidance explicitly calls out open RDP as a critical misconfiguration to remediate immediately.

## How Checkov evaluates this
This is implemented via a shared base class, `AbsSecurityGroupUnrestrictedIngress`, parameterized with `port=3389` for both the Terraform and CloudFormation checks. The base logic:

- Examines each ingress/inbound rule of the security group resource.
- For rules whose port range includes 3389 (i.e., `from_port <= 3389 <= to_port`, or an equivalent single-port match) and protocol is TCP (or "-1"/all), it checks the rule's source CIDR blocks.
- **FAIL**: if any matching rule's CIDR includes `0.0.0.0/0` (IPv4) or `::/0` (IPv6) — i.e., unrestricted access from any address.
- **PASS**: if port 3389 is not opened at all, or if it is restricted to specific CIDR ranges (e.g. a corporate VPN range or bastion host IP) rather than the full internet.

## Non-compliant example
```hcl
resource "aws_security_group" "windows_sg" {
  name   = "windows-rdp-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # unrestricted RDP access
  }
}
```

## Remediated example
```hcl
resource "aws_security_group" "windows_sg" {
  name   = "windows-rdp-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "RDP from corporate VPN only"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]   # <-- restricted to internal/VPN range
  }
}
```

## Remediation steps
1. Remove any ingress rule that opens TCP port 3389 to `0.0.0.0/0` or `::/0`.
2. Restrict RDP access to specific, known CIDR ranges (corporate VPN, bastion host, or a specific admin IP) rather than the full internet.
3. Prefer eliminating direct RDP exposure entirely: use AWS Systems Manager Session Manager, EC2 Instance Connect, or a bastion/jump host behind a VPN for remote administration instead of opening RDP publicly.
4. If RDP must remain open to a broad range temporarily, pair it with MFA-enforcing Network Access Control and enable detailed VPC Flow Logs / GuardDuty to detect brute-force attempts.
5. Apply the change — modifying a security group rule is non-disruptive to running instances (rule changes take effect immediately without instance restart).

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SecurityGroupUnrestrictedIngress3389.py)
- [Checkov CloudFormation check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SecurityGroupUnrestrictedIngress3389.py)
- [AWS: Security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
