# CKV2_AWS_19: Ensure that all EIP addresses allocated to a VPC are attached to EC2 instances

## Severity
**LOW** (score: 2.0/10)

Unattached Elastic IPs are an operational/cost hygiene issue with no meaningful direct security exposure.

## Summary
This check ensures that Elastic IP (EIP) addresses allocated for VPC use are actually attached to something (an EC2 instance, NAT gateway, or transfer server), not left dangling and unused.

## Applicability
**Checkov framework(s):** `terraform`

Terraform (AWS provider). Applies to `aws_eip` resources (with `vpc = true` or `domain = "vpc"`), evaluated in connection with `aws_instance`, `aws_eip_association`, `aws_nat_gateway`, or `aws_transfer_server`.

## Why it matters
An unattached Elastic IP is both a cost and a hygiene/security-posture issue. Cost-wise, AWS bills for EIPs that are allocated but not associated with a running instance (idle EIP charges). More importantly from a security-review standpoint, an orphaned EIP represents a reserved public IP address that isn't doing anything useful and complicates network inventory: reviewers auditing "what public IPs does this environment expose" can be misled by allocations that don't map to any actual running resource, or — in shared/large-account environments — a stale EIP could later be silently re-attached to an unintended or misconfigured resource, resurfacing an address that was assumed retired. Keeping infrastructure code free of orphaned resources is also basic Terraform hygiene, preventing "IaC drift" where the code no longer accurately reflects deployed intent.

## How Checkov evaluates this
This is a graph-based (JSON) policy that filters on `aws_eip` resources allocated for VPC use (`vpc = true` OR `domain = "vpc"`) and requires at least one of the following connection patterns:
1. The `aws_eip` is directly connected to an `aws_instance`, **or**
2. An `aws_eip_association` resource connects the `aws_eip` to an `aws_instance` and has its `instance_id` attribute set, **or**
3. The `aws_eip` is connected to an `aws_nat_gateway`, **or**
4. The `aws_eip` is connected to an `aws_transfer_server`, **or**
5. The `aws_eip`'s `instance` attribute references a `module.` or `data.` source (accounting for cases where the association is defined outside the current graph, e.g. via a module or data source Checkov can't fully resolve).

If none of these hold — the EIP is allocated for VPC use but has no resolvable attachment — the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_eip" "unused" {
  domain = "vpc"
  # Never referenced by an instance, NAT gateway, transfer server, or eip_association
}
```

## Remediated example
```hcl
resource "aws_instance" "app" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
}

resource "aws_eip" "app_eip" {
  domain   = "vpc"
  instance = aws_instance.app.id   # <-- fixed: EIP attached to a running instance
}
```

## Remediation steps
1. Attach every VPC-scoped EIP to a real resource: an EC2 instance (via `instance = ...` on `aws_eip` or a separate `aws_eip_association`), a NAT gateway, or a Transfer Family server.
2. If the EIP is genuinely no longer needed, release it — remove the `aws_eip` resource (and run `terraform apply` to actually deallocate it in AWS, since orphaned/idle EIPs still incur cost).
3. If the EIP is intentionally provisioned ahead of the instance it will attach to (e.g. reserved for a not-yet-created NAT gateway), consider whether it should be created in the same apply, or accept the check failing until the association is added.
4. Audit your AWS account periodically for unattached Elastic IPs outside of Terraform as well, since resources created manually or via other tooling won't show up in this Terraform-only graph check.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/EIPAllocatedToVPCAttachedEC2.json
