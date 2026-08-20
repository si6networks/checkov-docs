# CKV_AWS_315: Ensure EC2 Auto Scaling groups use EC2 launch templates

## Severity
**MEDIUM** (score: 5.0/10)

Using launch templates instead of legacy launch configurations is primarily a feature-completeness and maintainability best practice, with no direct exploitable security impact by itself.

## Summary
This check ensures Auto Scaling groups are provisioned using a `launch_template` (or a `mixed_instances_policy` that itself uses a launch template), rather than the legacy `launch_configuration` mechanism.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_autoscaling_group`

## Why it matters
Launch configurations are AWS's older, immutable, feature-limited mechanism for defining instance provisioning parameters. They cannot be versioned, don't support many current EC2 features (e.g., mixed instance types/purchase options, Nitro Enclaves, newer instance metadata service configuration such as enforcing IMDSv2, multiple ENIs at launch, or T-series unlimited credit specification defaults) and AWS has been steering customers away from them for years. From a security standpoint, launch templates are what allow you to enforce `metadata_options { http_tokens = "required" }` (IMDSv2 enforcement, closing the classic SSRF-to-credential-theft path) and to version and audit changes to instance configuration over time. Auto Scaling groups still relying on launch configurations often can't adopt these newer security controls at all, or must be migrated under production pressure during an incident.

## How Checkov evaluates this
The check inspects `aws_autoscaling_group` configuration:
- **PASS** if the resource has a top-level `launch_template` block, **or**
- **PASS** if it has a `mixed_instances_policy` block whose first entry itself contains a `launch_template` key.
- **FAIL** in all other cases — i.e., when the ASG is configured via the legacy `launch_configuration` attribute/resource instead.

## Non-compliant example
```hcl
resource "aws_launch_configuration" "example" {
  name          = "example-lc"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "t3.small"
}

resource "aws_autoscaling_group" "example" {
  name                 = "example-asg"
  min_size             = 1
  max_size             = 3
  desired_capacity     = 2
  vpc_zone_identifier  = [aws_subnet.a.id, aws_subnet.b.id]
  launch_configuration = aws_launch_configuration.example.name  # legacy mechanism
}
```

## Remediated example
```hcl
resource "aws_launch_template" "example" {
  name_prefix   = "example-lt-"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "t3.small"

  metadata_options {
    http_tokens = "required"          # bonus: enforce IMDSv2, only possible via launch templates
  }
}

resource "aws_autoscaling_group" "example" {
  name                = "example-asg"
  min_size            = 1
  max_size            = 3
  desired_capacity    = 2
  vpc_zone_identifier = [aws_subnet.a.id, aws_subnet.b.id]

  launch_template {                    # replaces launch_configuration
    id      = aws_launch_template.example.id
    version = "$Latest"
  }
}
```

## Remediation steps
1. Create an `aws_launch_template` resource that mirrors the settings of the existing `aws_launch_configuration` (AMI, instance type, security groups, IAM instance profile, user data, block device mappings).
2. Replace the ASG's `launch_configuration` argument with a `launch_template { id = ..., version = "$Latest" }` block (or use `mixed_instances_policy.launch_template` for mixed-instance strategies).
3. Take the opportunity to add `metadata_options { http_tokens = "required" }` to enforce IMDSv2 while migrating.
4. Test the change in a non-production ASG first — Terraform will replace the ASG's launch configuration reference in place, but instance refresh behavior should be verified (consider adding an `instance_refresh` block to roll instances onto the new template).
5. Once migrated, delete the now-unused `aws_launch_configuration` resource.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AutoScalingLaunchTemplate.py
- AWS docs: https://docs.aws.amazon.com/autoscaling/ec2/userguide/launch-templates.html
