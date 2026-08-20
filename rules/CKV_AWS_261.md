# CKV_AWS_261: Ensure HTTP HTTPS Target group defines Healthcheck

## Severity
**LOW** (score: 2.0/10)

A missing or inadequate health check only affects the load balancer's ability to detect and route around unhealthy targets, so the impact is primarily availability/resilience rather than a direct confidentiality or integrity compromise.

## Summary
This check ensures that any HTTP or HTTPS ALB/NLB target group defines a health check block with a configured path, so the load balancer can actively determine backend target health.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: resources `aws_lb_target_group`, `aws_alb_target_group` (protocol `HTTP` or `HTTPS` only — other protocols like `TCP` return `UNKNOWN`/not evaluated)

## Why it matters
Without an explicit health check path, a load balancer target group may fall back to defaults that don't accurately reflect application health (e.g., checking only TCP connectivity or the root `/` path when the real app doesn't serve meaningful content there), or checks may be missing entirely in some configurations. If unhealthy targets aren't detected and removed from rotation, the load balancer will continue routing live traffic to instances that are crashed, deploying, out of memory, or otherwise unable to serve requests — causing partial outages, elevated error rates, and poor failover behavior during deployments or instance replacement. This check is rooted in PCI DSS v3.2.1 operational-resilience requirements: reliable health checking is a baseline expectation for internet-facing payment infrastructure, since a broken health check can silently degrade availability and mask instance-level compromise or failure.

## How Checkov evaluates this
The check (`LBTargetGroupDefinesHealthCheck`) runs only when `protocol` is exactly `["HTTP"]` or `["HTTPS"]`:
- If `protocol` is some other value (e.g., `TCP`, `UDP`, `TLS`, `GENEVE`), the check returns `UNKNOWN` (not applicable).
- If protocol is HTTP/HTTPS, it looks for a `health_check` block. If present, it checks that the first `health_check` entry is a dict and has a non-empty `path` key.
- **PASS**: `health_check` block exists and specifies a `path`.
- **FAIL**: no `health_check` block at all, or a `health_check` block without a `path`.

## Non-compliant example
```hcl
resource "aws_lb_target_group" "app" {
  name     = "app-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
  # no health_check block defined
}
```

## Remediated example
```hcl
resource "aws_lb_target_group" "app" {
  name     = "app-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/healthz"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200"
  }
}
```

## Remediation steps
1. Add a `health_check` block to every `aws_lb_target_group`/`aws_alb_target_group` with `protocol = "HTTP"` or `"HTTPS"`.
2. Set `path` to a real, lightweight application endpoint (e.g. `/healthz`, `/status`) that verifies the app can serve traffic — not just that the process is running.
3. Tune `interval`, `timeout`, `healthy_threshold`, and `unhealthy_threshold` to match the deployment's startup time and acceptable failover latency.
4. Set `matcher` to the expected success HTTP status code(s) so transient 5xx responses trigger target removal.
5. No resource replacement required; target groups can be updated in place, though ELB health-check changes take effect on the next check cycle.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LBTargetGroupsDefinesHealthcheck.py
- AWS documentation: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-health-checks.html
