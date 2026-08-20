# CKV_AWS_378: Ensure AWS Load Balancer doesn't use HTTP protocol

## Severity
**HIGH** (score: 7.5/10)

An ALB/NLB target group or listener configured for plain HTTP instead of HTTPS transmits application traffic unencrypted, exposing sensitive data and session tokens to network eavesdropping.

## Summary
This check ensures that Application/Network Load Balancer target groups (and any listener attached to them) do not use plaintext `HTTP` as the protocol, so traffic between the load balancer and backend targets (and/or clients) is encrypted.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_lb_target_group`, `aws_alb_target_group`, `aws_lb_listener`, `aws_alb_listener` (this is a graph-based check that correlates target groups with their connected listeners)

## Why it matters
An ELBv2 (ALB/NLB) target group configured with `protocol = "HTTP"` sends traffic to backend targets unencrypted. If a listener attached to that target group is also `HTTP`, then client-facing traffic is unencrypted end-to-end. This exposes:

- Credentials, session cookies, API tokens, and application data to interception by anyone able to observe the network path (compromised peer instance, misconfigured VPC peering/routing, malicious insider, or an attacker who has gained a foothold elsewhere in the VPC).
- Traffic tampering, since plaintext HTTP has no integrity protection.

Because AWS network segmentation is not an absolute guarantee against lateral movement, defense-in-depth calls for TLS even for "internal" load-balanced traffic, not just the internet-facing hop.

## How Checkov evaluates this
This is a **graph-based JSON policy** (`LBTargetGroup.json`), not a Python check. Its logic (an `or` of two branches) is:

1. **Branch A (direct attribute):** The check passes if the target group's own `protocol` attribute is not equal to `HTTP` (for `aws_lb_target_group` or `aws_alb_target_group`).
2. **Branch B (connection-based, only relevant when Branch A's condition doesn't hold, i.e., target group protocol *is* HTTP):** filters to `aws_lb_target_group`/`aws_alb_target_group` resources, requires a graph connection to exist between that target group and an `aws_lb_listener`/`aws_alb_listener`, and then requires the connected listener's `protocol` attribute to also not equal `HTTP`.

In short: a target group using `HTTP` protocol only fails if it is also connected to a listener whose protocol is `HTTP` (or if it has no listener connection to redeem it via Branch B failing to establish PASS through the `or`). Practically, the check flags plaintext HTTP configurations across the target-group/listener pair, not just an isolated attribute.

## Non-compliant example
```hcl
resource "aws_lb_target_group" "example" {
  name     = "example-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.example.id
}

resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.example.arn
  }
}
```

## Remediated example
```hcl
resource "aws_lb_target_group" "example" {
  name     = "example-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.example.id
}

resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.example.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.example.arn
  }
}
```

## Remediation steps
1. Change the target group's `protocol` to `HTTPS` (or another non-HTTP protocol appropriate to your workload, such as `TCP`/`TLS` for NLBs where relevant).
2. Change the associated listener's `protocol` to `HTTPS`, add `certificate_arn` (an ACM or IAM certificate ARN) and a modern `ssl_policy`.
3. Ensure the backend target (EC2 instance, ECS task, Lambda) actually terminates or re-encrypts TLS on the matching port — changing only the Terraform protocol attribute without the backend listening on TLS will break connectivity.
4. If backend re-encryption is not feasible short-term, consider TLS termination at the ALB with encryption maintained internally only where compliance truly requires it, and document/justify any exception.
5. This typically does not require target-group replacement, but changing `protocol`/`port` on an `aws_lb_target_group` can force resource replacement in some Terraform AWS provider versions — review the plan output carefully before applying.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/LBTargetGroup.json)
- [AWS Application Load Balancer listener documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html)
