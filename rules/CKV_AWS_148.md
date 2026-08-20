# CKV_AWS_148: Ensure no default VPC is planned to be provisioned
## Severity
**LOW** (score: 2.0/10)

Default VPCs come with permissive out-of-the-box networking (broad default security group, all subnets auto-assign public IPs) that is easy to misconfigure or overlook, so provisioning one increases the chance of unintended network exposure even though it is not itself an active breach.

## Summary
This check flags any Terraform configuration that declares an `aws_default_vpc` resource, since the presence of that resource block means Terraform will manage (and, on `apply`, adopt/create) the account's default VPC.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to the `aws_default_vpc` resource.

## Why it matters
AWS's auto-created default VPC ships with permissive out-of-the-box settings: all subnets are public by default (auto-assign public IP enabled), a default security group that historically allows broad intra-VPC traffic, and a single flat address space with no intentional network segmentation between tiers (e.g. no separation of a database subnet from a public-facing web subnet). Workloads launched into the default VPC without further hardening are more likely to be inadvertently internet-reachable, and the lack of deliberate subnetting/route-table design makes it harder to enforce network-level blast-radius controls. Because this resource always represents "the account's implicit legacy network," Checkov treats its mere declaration as a signal of network design debt — the recommended practice is to build purpose-designed custom VPCs (via `aws_vpc`) with explicit subnets, route tables, and NACLs, and to leave the default VPC deleted or unused.

## How Checkov evaluates this
The check's `scan_resource_conf` unconditionally returns `CheckResult.FAILED` for every `aws_default_vpc` resource found in configuration — there is no passing configuration for this resource type; any use of it is a finding. It applies regardless of what attributes are set inside the block.

## Non-compliant example
```hcl
resource "aws_default_vpc" "default" {
  tags = {
    Name = "Default VPC"
  }
}
```

## Remediated example
```hcl
# Remove the aws_default_vpc resource entirely and define a custom VPC instead.

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "main-vpc"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "main-private-a"
  }
}
```

## Remediation steps
1. Remove the `aws_default_vpc` resource block from your Terraform configuration.
2. Design and provision a purpose-built `aws_vpc` with explicit public/private subnets, route tables, and NAT/Internet gateways matching your architecture.
3. If the default VPC already exists in the account and is unused, consider deleting it manually (`aws ec2 delete-vpc`) after confirming nothing depends on it, rather than importing/managing it in Terraform.
4. If you must keep a default VPC for legacy reasons (e.g. some AWS services assume its existence), be explicit about accepting the risk and add compensating controls (deny public subnet auto-assign IP, tighten the default security group) rather than relying on Terraform to "manage" it as-is.
5. Note: destroying the default VPC managed via `aws_default_vpc` in Terraform does not actually delete the default VPC in AWS (the resource is adopt-only) — removing the block from Terraform simply stops managing it, it does not recreate a "safer" default.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/VPCDefaultNetwork.py
- AWS docs: https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html
