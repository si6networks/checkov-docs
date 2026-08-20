# CKV_AWS_24: Ensure no security groups allow ingress from 0.0.0.0:0 to port 22

## Severity
**CRITICAL** (score: 9.2/10)

A security group allowing 0.0.0.0/0 ingress on SSH (22) directly exposes every attached instance to internet-wide brute-force and credential-stuffing attacks, one of the most common and consequential cloud misconfigurations leading to full host compromise.

## Summary
This check ensures that no security group rule allows unrestricted (`0.0.0.0/0`) inbound access to TCP port 22 (SSH).

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:**
  - CloudFormation: `AWS::EC2::SecurityGroup`, `AWS::EC2::SecurityGroupIngress`
  - Terraform: `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`

## Why it matters
Security groups are the primary instance-level firewall in AWS, and port 22 is the standard SSH port for remote administration of Linux hosts. Leaving SSH open to `0.0.0.0/0` exposes any attached instance directly to the entire internet, making it a prime target for automated brute-force and credential-stuffing bots that continuously scan for open port 22 across the whole IPv4 address space. This is one of the single most common and most consequential cloud misconfigurations — it appears at the top of virtually every cloud security benchmark (CIS AWS Foundations, PCI-DSS scoping guidance, NIST references) precisely because a compromised SSH service typically leads directly to full host compromise, and from there to lateral movement, data exfiltration, or ransomware deployment. Unlike a NACL misconfiguration (which affects an entire subnet), an open security group rule affects every instance to which that specific security group is attached — often a whole fleet behind an Auto Scaling group — multiplying the blast radius of a single Terraform/CloudFormation mistake.

## How Checkov evaluates this
Both implementations subclass a shared abstract base (`AbsSecurityGroupUnrestrictedIngress`) parameterized with `port=22`, which inspects security group ingress rules for the combination of:
- The rule direction is ingress (not egress).
- The source CIDR is fully open — `0.0.0.0/0` (IPv4) or `::/0` (IPv6).
- The protocol is TCP (or `-1`/all, which implicitly includes TCP).
- The port range (`from_port`–`to_port` in Terraform, `FromPort`–`ToPort` in CloudFormation) includes port 22.

If a rule (inline in the security group resource, or a standalone `aws_security_group_rule`/`AWS::EC2::SecurityGroupIngress`) matches all of these, the check **FAILS**. Restricting the CIDR to a specific range, using a non-TCP-inclusive protocol, or excluding port 22 from the range causes the check to **PASS**.

## Non-compliant example
```hcl
resource "aws_security_group" "app" {
  name   = "app-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

## Remediated example
```hcl
resource "aws_security_group" "app" {
  name   = "app-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "SSH from bastion/VPN only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # internal management CIDR only
  }
}
```

## Remediation steps
1. Identify the flagged security group rule permitting port 22 from `0.0.0.0/0`.
2. Restrict `cidr_blocks`/`ipv6_cidr_blocks` (or the equivalent CloudFormation `CidrIp`) to specific, known source ranges — a bastion host, VPN gateway, or corporate IP range.
3. Where possible, eliminate direct SSH exposure entirely by using AWS Systems Manager Session Manager, which requires no inbound port to be opened at all.
4. If SSH access is still required, enforce key-based authentication, disable password login, and consider placing the instance behind a bastion host or Client VPN as the sole path in.
5. This is a metadata-only change to the security group and does not require instance replacement or downtime; changes typically take effect immediately.

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SecurityGroupUnrestrictedIngress22.py)
- [Checkov CloudFormation check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SecurityGroupUnrestrictedIngress22.py)
- [AWS Security Groups documentation](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
