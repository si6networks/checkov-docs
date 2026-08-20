# CKV_AWS_2: Ensure ALB protocol is HTTPS
## Severity
**HIGH** (score: 7.5/10)

An ALB listener that isn't restricted to HTTPS/TLS allows client traffic to traverse the load balancer in plaintext, exposing requests, responses, and any embedded credentials to interception on the network path.

## Summary
Ensures that Application/Network Load Balancer listeners either terminate traffic using a secure protocol (HTTPS/TLS/TCP/UDP/TCP_UDP) or, if using plain HTTP, redirect it to HTTPS.

## Applicability
- **Terraform**: `aws_lb_listener`, `aws_alb_listener` — inspects the `protocol` attribute and, when `HTTP`, the `default_action` redirect configuration.
- **CloudFormation**: `AWS::ElasticLoadBalancingV2::Listener` — inspects `Properties/Protocol` and `Properties/DefaultActions`.

## Why it matters
A listener configured for plain HTTP without a redirect to HTTPS transmits all request/response data — including cookies, session tokens, authentication headers, and form/API payloads — in cleartext between the client and the load balancer. This exposes traffic to:
- Passive eavesdropping (e.g., on shared/compromised networks, malicious Wi-Fi, or a compromised upstream router) that can capture credentials or session tokens.
- Active man-in-the-middle attacks that can inject or modify content since there is no integrity protection.
- Failing compliance requirements (PCI-DSS, HIPAA) that mandate encryption in transit for cardholder or health data.

Even when the backend/target group uses HTTPS, if the *listener* itself accepts plain HTTP without a redirect, any client that connects over HTTP never gets upgraded, silently exposing that portion of traffic.

## How Checkov evaluates this
Both implementations look at the listener's `Protocol`/`protocol`:
- If it is one of `HTTPS`, `TLS`, `TCP`, `UDP`, `TCP_UDP` → PASS (these are inherently encrypted or non-HTTP transport protocols where TLS is handled elsewhere, e.g. NLB pass-through).
- If it is `HTTP`, the check inspects `DefaultActions`/`default_action`:
  - If the default action's `type` is `redirect` and the redirect's `Protocol`/`protocol` is `HTTPS` → PASS (HTTP is safely redirected to HTTPS).
  - Otherwise → FAIL.
- CloudFormation additionally returns `UNKNOWN` if `DefaultActions` uses a CloudFormation intrinsic/condition function (e.g., `Fn::If`), since the actual value can't be statically resolved.
- Terraform additionally returns `UNKNOWN` if the protocol is a variable-dependent expression that can't be resolved statically, or if the redirect protocol itself can't be resolved.

## Non-compliant example
```hcl
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"   # FAILS CKV_AWS_2 - no redirect to HTTPS

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
```

## Remediated example
```hcl
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"          # fix: redirect HTTP -> HTTPS

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https_listener" {
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
1. Change the listener's `protocol` to `HTTPS` (or `TLS` for NLB) and attach a valid ACM/IAM server certificate via `certificate_arn`.
2. If you must keep a port-80 listener for backward compatibility, set its `default_action.type = "redirect"` with `redirect.protocol = "HTTPS"` and an appropriate `status_code` (`HTTP_301`).
3. Choose a modern `ssl_policy` (e.g., `ELBSecurityPolicy-TLS13-1-2-2021-06`) on the HTTPS listener to disable weak ciphers/TLS versions.
4. For CloudFormation, ensure `DefaultActions[0].RedirectConfig.Protocol` is `HTTPS` when `Protocol` is `HTTP`.
5. Adding a new HTTPS listener alongside the redirect is typically non-disruptive; removing the old HTTP forward action should be done only after clients have migrated, since a hard cutover could break clients hard-coded to `http://`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ALBListenerHTTPS.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ALBListenerHTTPS.py
- AWS docs: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html
