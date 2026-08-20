# CKV_AWS_389: Ensure AWS Auto Scaling group launch configuration doesn't have public IP address assignment enabled

## Severity
**MEDIUM** (score: 5.5/10)

Auto-assigning public IP addresses to instances launched from an Auto Scaling launch configuration increases the instances' internet-facing attack surface, though actual exposure still depends on the associated security group rules.

## Summary
This check ensures an EC2 Auto Scaling launch configuration does not automatically assign a public IP address to the instances it launches.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_launch_configuration`

## Why it matters
When `associate_public_ip_address = true` on a launch configuration, every instance the Auto Scaling group launches from it is automatically given a public IP address and is directly reachable from the internet (subject to security group and NACL rules). This is risky because:

- It significantly enlarges the internet-facing attack surface — every scaled-out instance becomes a potential direct target for port scanning, exploitation attempts, and DDoS, rather than only a controlled front door (like a load balancer or bastion) being exposed.
- Fleet instances behind an ASG are typically meant to be reached only via a load balancer, VPN, or bastion; giving every instance its own public IP defeats that architecture and increases the chance that a misconfigured security group (even temporarily, during a change) directly exposes application ports to the internet.
- It also complicates network security auditing, since the set of "internet-reachable" hosts grows and shrinks dynamically with the ASG rather than being a fixed, reviewable set of ingress points.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` with a single forbidden value: the `associate_public_ip_address` attribute must not be `True`. If it is explicitly `true`, the check **FAILS**. If it is `false`, or the attribute is omitted (Terraform/AWS will default based on the subnet's `map_public_ip_on_launch` setting, but Checkov treats the absence of an explicit `true` as passing), the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_launch_configuration" "example" {
  name_prefix                = "example-lc-"
  image_id                   = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true

  lifecycle {
    create_before_destroy = true
  }
}
```

## Remediated example
```hcl
resource "aws_launch_configuration" "example" {
  name_prefix                = "example-lc-"
  image_id                   = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = false

  lifecycle {
    create_before_destroy = true
  }
}
```

## Remediation steps
1. Set `associate_public_ip_address = false` explicitly on the launch configuration.
2. Ensure the Auto Scaling group launches instances into private subnets, using a NAT Gateway (or VPC endpoints) for any required outbound internet access instead of a direct public IP.
3. Place a load balancer (ALB/NLB) in public subnets as the sole internet-facing entry point, forwarding to the private instances in the ASG.
4. If instances genuinely need to be internet-reachable individually (uncommon for ASG members), reconsider the architecture — this is rarely the right pattern for scaled fleets — or scope exposure tightly via security groups and document the exception.
5. Note: `aws_launch_configuration` is a legacy resource; AWS/Terraform recommend migrating to `aws_launch_template` for new work, which offers more granular network interface configuration alongside this same setting.
6. Changing this attribute on an existing launch configuration typically requires creating a new launch configuration (they are immutable) and updating the ASG to reference it — no downtime for running instances, but new instances launched after the change will follow the new setting.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AutoScalingGroupWithPublicAccess.py)
- [AWS Auto Scaling launch configuration documentation](https://docs.aws.amazon.com/autoscaling/ec2/userguide/launch-configurations.html)
