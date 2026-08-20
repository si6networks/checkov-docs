# CKV2_AWS_20: Ensure that ALB redirects HTTP requests into HTTPS ones

## Severity
**MEDIUM** (score: 5.0/10)

An ALB that does not redirect HTTP to HTTPS allows client traffic to be sent or received unencrypted, exposing it to interception, though HTTPS listeners may still be available in parallel.

## Summary
This check ensures that an Application/Classic Load Balancer's HTTP (port 80) listener, if present, redirects traffic to HTTPS rather than serving plaintext content directly.

## Applicability
Terraform (AWS provider). Applies to `aws_lb`/`aws_alb` resources, evaluated in connection with their `aws_lb_listener`/`aws_alb_listener` resources.

## Why it matters
If an ALB has a listener on port 80/HTTP that forwards traffic to a target group instead of redirecting to HTTPS, all client-to-load-balancer traffic on that path — including cookies, authentication tokens, form submissions, and session identifiers — travels unencrypted across the internet. This exposes users to network-level eavesdropping and session hijacking (e.g. over public Wi-Fi, compromised ISPs, or any on-path attacker), and undermines any HTTPS protections configured elsewhere, since users who type `http://` or follow an `http://` link get served content in the clear rather than being upgraded to TLS. Enforcing an HTTP→HTTPS redirect at the load balancer ensures encryption in transit is applied consistently regardless of how a client initially connects, which is required by most compliance frameworks (PCI-DSS, HIPAA) and is standard web security practice (also enabling HSTS to work correctly).

## How Checkov evaluates this
This is a graph-based (JSON) policy that filters on `aws_lb`/`aws_alb` resources and **PASSES** if either:
1. No `aws_lb_listener`/`aws_alb_listener` is connected to the load balancer at all (nothing to redirect — out of scope), **or**
2. A listener is connected, and for every such listener either:
   - The listener's `port` is not `"80"` **and** `protocol` is not `"HTTP"` (i.e. it's not a plaintext HTTP listener at all), **or**
   - The listener **is** port 80/HTTP, but its `default_action.type` equals `"redirect"`, `default_action.redirect.*.port` equals `"443"`, and `default_action.redirect.*.protocol` equals `"HTTPS"` — i.e., it exists specifically to redirect to HTTPS.

If a port-80/HTTP listener exists and its default action is anything other than a redirect to port 443/HTTPS (e.g. it forwards directly to a target group), the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_lb" "app" {
  name               = "app-alb"
  load_balancer_type = "application"
  subnets            = [aws_subnet.a.id, aws_subnet.b.id]
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"          # serves plaintext HTTP directly
    target_group_arn = aws_lb_target_group.app.arn
  }
}
```

## Remediated example
```hcl
resource "aws_lb" "app" {
  name               = "app-alb"
  load_balancer_type = "application"
  subnets            = [aws_subnet.a.id, aws_subnet.b.id]
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"                     # <-- fixed: redirect to HTTPS
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.app.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
```

## Remediation steps
1. On any `aws_lb_listener`/`aws_alb_listener` with `port = 80` and `protocol = "HTTP"`, change `default_action` to `type = "redirect"` with a nested `redirect` block specifying `port = "443"`, `protocol = "HTTPS"`, and `status_code = "HTTP_301"`.
2. Add a corresponding HTTPS listener on port 443 with a valid ACM certificate (`certificate_arn`) and a modern `ssl_policy` (e.g. TLS 1.2+), forwarding to the actual target group.
3. If the load balancer genuinely needs no HTTP listener at all (clients always connect via HTTPS), simply remove the port-80 listener entirely rather than leaving it forwarding.
4. Add HSTS headers at the application layer once redirects are in place, so browsers cache the upgrade-to-HTTPS instruction and skip the initial plaintext round-trip on subsequent visits.
5. This check is Terraform-graph-based; equivalent misconfigurations in CloudFormation/CDK for the same resource types are not covered by this specific rule ID.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/ALBRedirectsHTTPToHTTPS.json
