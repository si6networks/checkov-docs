# CKV_AWS_153: Autoscaling groups should supply tags to launch configurations
## Severity
**LOW** (score: 2.0/10)

Missing tags on autoscaling launch configurations is an operational/hygiene gap (cost allocation, resource identification) with no direct exploitability or security impact on its own.

## Summary
This check verifies that an `aws_autoscaling_group` resource specifies a `tag` or `tags` block, ensuring instances launched by the group are tagged.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to the `aws_autoscaling_group` resource.

## Why it matters
Instances launched by an Auto Scaling group are ephemeral and created/destroyed automatically as the group scales — without propagated tags, these instances lack the ownership, cost-center, environment, and application metadata that tagging conventions rely on. This has direct security and operational consequences: cost-allocation and chargeback reports become inaccurate, automated security tooling and IAM condition keys that key off tags (e.g. `aws:ResourceTag/Environment`) silently fail to apply to these instances, and incident responders lose a fast way to identify what an instance is/owns it during a live investigation. Untagged fleets of auto-scaled instances are a common source of "mystery resource" findings in cost and security audits.

## How Checkov evaluates this
Custom `scan_resource_conf`: checks whether the resource configuration dictionary has a `tag` key or a `tags` key present at all (any non-empty declaration of either block/attribute). If either is present → `PASSED`. If neither is present → `FAILED`. Note the check only verifies *presence* of a tag/tags block, not that `propagate_at_launch` is set or that specific tag keys exist.

## Non-compliant example
```hcl
resource "aws_autoscaling_group" "app" {
  name                = "app-asg"
  min_size            = 2
  max_size            = 6
  desired_capacity    = 2
  vpc_zone_identifier = var.private_subnet_ids

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
}
```

## Remediated example
```hcl
resource "aws_autoscaling_group" "app" {
  name                = "app-asg"
  min_size            = 2
  max_size            = 6
  desired_capacity    = 2
  vpc_zone_identifier = var.private_subnet_ids

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  tag { # <-- added
    key                 = "Name"
    value               = "app-asg-instance"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = "production"
    propagate_at_launch = true
  }
}
```

## Remediation steps
1. Add one or more `tag { key = ... value = ... propagate_at_launch = true }` blocks (or a `tags` map on older provider versions) to the `aws_autoscaling_group` resource.
2. Set `propagate_at_launch = true` for any tag you want copied onto the actual EC2 instances the group launches — the block only satisfying the check does not guarantee propagation on its own.
3. Standardize on your organization's required tag keys (e.g. `Name`, `Environment`, `Owner`, `CostCenter`) across all ASGs for consistent cost/security reporting.
4. Consider using a shared Terraform module or `default_tags` at the provider level to enforce this consistently across many ASGs.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AutoScalingTagging.py
- AWS docs: https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-tagging.html
