# CKV2_AWS_15: Ensure that auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing health checks

## Severity
**MEDIUM** (score: 3.5/10)

Missing ELB-based health checks on an Auto Scaling group affects availability by allowing unhealthy instances to keep receiving traffic, but has no direct confidentiality or integrity impact.

## Summary
This check ensures that an Auto Scaling Group (ASG) attached to a Classic ELB or ALB/NLB target group uses ELB-based health checks (`health_check_type = "ELB"`) rather than relying solely on basic EC2 instance-status health checks.

## Applicability
**Checkov framework(s):** `terraform`

Terraform (AWS provider). Applies to `aws_autoscaling_group` resources connected via `aws_autoscaling_attachment` to `aws_elb` or `aws_lb_target_group`.

## Why it matters
The default ASG health check (`EC2`) only detects whether the underlying instance is running at the hypervisor/OS level — it has no visibility into whether the application on that instance is actually serving traffic correctly. An instance can be "healthy" by EC2's definition (booted, passing system status checks) while its web server has crashed, is deadlocked, is returning 500s, or has lost a database connection. When the ASG is fronted by a load balancer, using `health_check_type = "ELB"` means the ASG defers to the load balancer's application-level health checks (e.g. an HTTP GET to `/healthz`), so unhealthy-but-running instances are detected and automatically replaced. Without this, a broken instance can stay in service indefinitely (or until manually noticed), degrading availability and potentially serving errors or stale/insecure content to users — an availability and incident-response gap, not just a cosmetic one.

## How Checkov evaluates this
This is a graph-based (JSON) policy filtering on `aws_autoscaling_attachment` resources. It requires ALL of:
1. `aws_autoscaling_group.health_check_type` **equals** `"ELB"`.
2. The ASG is connected to an `aws_autoscaling_attachment`.
3. Either: the attachment connects to an `aws_elb` that has a `health_check` block defined, **or** it connects to an `aws_lb_target_group` that has a `health_check` block defined.

If `health_check_type` is not `"ELB"` (e.g. left at the default `"EC2"`), or the attached ELB/target group lacks a `health_check` configuration, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_elb" "app_elb" {
  name               = "app-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
}

resource "aws_autoscaling_group" "app_asg" {
  min_size            = 2
  max_size            = 5
  vpc_zone_identifier = [aws_subnet.a.id, aws_subnet.b.id]
  launch_template {
    id = aws_launch_template.app.id
  }
  # health_check_type defaults to "EC2" — not attuned to app health
}

resource "aws_autoscaling_attachment" "app_attach" {
  autoscaling_group_name = aws_autoscaling_group.app_asg.id
  elb                    = aws_elb.app_elb.id
}
```

## Remediated example
```hcl
resource "aws_elb" "app_elb" {
  name               = "app-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  health_check {                        # <-- fixed: ELB has a health check defined
    target              = "HTTP:80/healthz"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_autoscaling_group" "app_asg" {
  min_size            = 2
  max_size            = 5
  vpc_zone_identifier  = [aws_subnet.a.id, aws_subnet.b.id]
  health_check_type    = "ELB"          # <-- fixed: ASG defers to ELB health checks
  health_check_grace_period = 300
  launch_template {
    id = aws_launch_template.app.id
  }
}

resource "aws_autoscaling_attachment" "app_attach" {
  autoscaling_group_name = aws_autoscaling_group.app_asg.id
  elb                    = aws_elb.app_elb.id
}
```

## Remediation steps
1. Set `health_check_type = "ELB"` on the `aws_autoscaling_group`.
2. Set an appropriate `health_check_grace_period` so instances aren't marked unhealthy and terminated before the application has finished starting up.
3. Define a `health_check` block on the attached `aws_elb`, or on the `aws_lb_target_group` if using an ALB/NLB, pointing to a meaningful application health endpoint (not just a TCP port check where possible).
4. Ensure the health check path/endpoint reflects true application health (e.g. checks downstream dependencies) rather than always returning 200 regardless of internal state.
5. Test the failover behavior by intentionally breaking the health endpoint on one instance and confirming the ASG replaces it.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/AutoScallingEnabledELB.json
