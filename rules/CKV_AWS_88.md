# CKV_AWS_88: EC2 instance should not have public IP.

## Severity
**HIGH** (score: 7.8/10)

Assigning a public IP to an EC2 instance widens its network attack surface to the internet, making any exposed service or misconfigured security group directly reachable by external attackers.

## Summary
This check fails when an EC2 instance, launch template, or Ansible `ec2_instance` task explicitly requests a public IP address (`associate_public_ip_address` / `assign_public_ip` set to `true`), which would make the instance directly reachable from the internet.

## Applicability
- **Terraform**: `aws_instance` (`associate_public_ip_address` attribute) and `aws_launch_template` (`network_interfaces[0].associate_public_ip_address`).
- **CloudFormation**: `AWS::EC2::Instance` and `AWS::EC2::LaunchTemplate` — inspects `NetworkInterfaces[].AssociatePublicIpAddress` (top-level for Instance, under `LaunchTemplateData` for LaunchTemplate).
- **Ansible**: tasks using the `amazon.aws.ec2_instance` or `ec2_instance` modules — inspects `network.assign_public_ip`, including tasks nested inside `block`/`tasks` structures at various depths.

## Why it matters
An EC2 instance with a public IP is directly addressable from the internet. Even with security groups configured, this expands the attack surface considerably: it makes the instance a target for internet-wide scanning and exploitation of any exposed service, removes the layered defense that a private subnet + NAT gateway + bastion/SSM architecture provides, and increases the blast radius if a security group rule is ever misconfigured or overly permissive (a single bad `0.0.0.0/0` rule on a public instance is directly exploitable, whereas on a private instance it is not). Public IPs on instances also complicate IP-based allowlisting and increase exposure to DDoS and credential-stuffing style scanning aimed at management ports (SSH/RDP/WinRM).

## How Checkov evaluates this
- **Terraform** (`aws_instance` / `aws_launch_template`): `BaseResourceNegativeValueCheck` inspects `associate_public_ip_address` for `aws_instance`, or `network_interfaces/[0]/associate_public_ip_address` for `aws_launch_template`. The forbidden value is `True` — if either key is explicitly set to `true`, the check fails.
- **CloudFormation**: walks `Properties.NetworkInterfaces` (or `LaunchTemplateData.NetworkInterfaces` for a launch template). If any network interface entry has `AssociatePublicIpAddress: true`, the check FAILS. If the key is present but not `true`, it continues. If the key is absent entirely, the result is `UNKNOWN` — AWS's actual default behavior (assign a public IP or not) depends on whether the subnet's `MapPublicIpOnLaunch` is true, which cannot be determined from the template alone.
- **Ansible**: only applies when `image_id`/`image` is set in the task (i.e., a new instance is being launched, not one that already exists — in which case the result is `UNKNOWN`). Then it inspects `network.assign_public_ip`; expected value is `False`.

## Non-compliant example
```hcl
resource "aws_instance" "web" {
  ami                          = "ami-0abcdef1234567890"
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.public.id
  associate_public_ip_address = true
}
```

## Remediated example
```hcl
resource "aws_instance" "web" {
  ami                          = "ami-0abcdef1234567890"
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.private.id
  associate_public_ip_address = false   # instance stays reachable only via NAT/bastion/SSM
}
```

## Remediation steps
1. Set `associate_public_ip_address = false` (Terraform `aws_instance`) or the equivalent on `network_interfaces` for `aws_launch_template`.
2. Move the instance to a private subnet and provide outbound internet access, if needed, via a NAT Gateway.
3. For administrative access, use AWS Systems Manager Session Manager (no inbound ports needed) instead of exposing SSH/RDP publicly.
4. If a public-facing service is genuinely required, put it behind an Application/Network Load Balancer or CloudFront, and keep the instance itself private.
5. For CloudFormation, be aware that omitting `AssociatePublicIpAddress` does not guarantee a private instance — the subnet's `MapPublicIpOnLaunch` setting decides the default, so set the property explicitly to `false` rather than relying on the subnet configuration.
6. For Ansible `ec2_instance` tasks, set `network.assign_public_ip: false` when launching new instances.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EC2PublicIP.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/EC2PublicIP.py
- Checkov check source (Ansible): https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/task/aws/EC2PublicIP.py
- AWS docs: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html
