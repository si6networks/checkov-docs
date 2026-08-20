# CKV2_AWS_5: Ensure that Security Groups are attached to another resource
## Severity
**LOW** (score: 2.0/10)

An unattached security group poses no direct exposure by itself; it is a hygiene/cleanup finding aimed at reducing configuration clutter rather than closing an active attack path.

## Summary
This check fails when an `aws_security_group` resource exists in the Terraform configuration but is not attached (via a graph connection) to any of a long list of supported networked resources such as EC2 instances, load balancers, RDS instances, Lambda functions, EKS clusters, and others.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_security_group` (checked for connections to `aws_alb`, `aws_instance`, `aws_db_instance`, `aws_lambda_function`, `aws_eks_cluster`, `aws_elb`, `aws_ecs_service`, `aws_lb`, `aws_rds_cluster`, `aws_launch_template`, and dozens of other networked AWS resource types)

## Why it matters
An unattached security group is dead configuration — it enforces nothing on its own, since security groups only take effect when associated with an ENI-backed resource. Its presence in the codebase is a signal of one of two problems: either it's orphaned leftover config from a resource that was since removed or renamed (and the security group's carefully-scoped rules are simply unused clutter that adds noise and confusion during audits), or — more concerning — the intended attachment was forgotten, meaning the resource it was meant to protect is instead relying on the default security group (which in many accounts still allows broad intra-VPC access) or another overly permissive group. Unused security groups also accumulate over time and make it harder for reviewers to reason about the actual network exposure of a VPC, since they can't tell at a glance whether a given rule set is actually enforced anywhere.

## How Checkov evaluates this
This is a graph-based JSON policy that:
1. Filters to resources of type `aws_security_group`.
2. Requires a graph `connection` (via the `networking` attribute path, i.e., a `vpc_security_group_ids`, `security_groups`, or `network_interface`-style reference) from the security group to at least one resource in a large allow-list of connected resource types (ALB/ELB/NLB, EC2 instances/launch templates/launch configurations/spot requests, RDS/Aurora/DocumentDB/Neptune/Redshift, ElastiCache, OpenSearch/Elasticsearch, EKS/EMR, Lambda, MSK/MQ, EFS/FSx file systems, VPC endpoints, Client VPN, Transfer Family, SageMaker notebooks, and more).
- **PASS** if the security group has at least one such connection.
- **FAIL** if the security group has zero connections to any resource in the supported list — meaning it is defined but never referenced/attached anywhere in the given configuration.
- Note: this is a single-configuration graph check — if the security group is attached to a resource defined in a different, unrelated Terraform root module/state that Checkov isn't scanning together, it may report a false positive; verify actual usage in your infrastructure before assuming it's truly orphaned.

## Non-compliant example
```hcl
resource "aws_security_group" "orphaned" {
  name        = "orphaned-sg"
  description = "Allow app traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
# No resource anywhere references aws_security_group.orphaned
```

## Remediated example
```hcl
resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Allow app traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_instance" "app" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.app.id
  vpc_security_group_ids = [aws_security_group.app.id] # attaches the group
}
```

## Remediation steps
1. Determine whether the unattached security group is genuinely unused; if so, delete the resource block (and its corresponding AWS resource) rather than leaving dead configuration behind.
2. If it was meant to protect a specific resource, attach it via the appropriate attribute — `vpc_security_group_ids` (EC2, RDS), `security_groups` (ELB/classic), `network_interface { security_groups = [...] }`, or the resource-specific equivalent.
3. Search the broader codebase/other modules for references to the security group's ID output if Checkov is only scanning part of a multi-module setup, to rule out a false positive before deleting.
4. Consider using `terraform state list` / `aws ec2 describe-network-interfaces --filters Name=group-id,Values=<sg-id>` against the real environment to confirm zero attachments before removing a group that manages production traffic.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/SGAttachedToResource.json
