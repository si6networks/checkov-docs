# CKV_AWS_103: Ensure that Load Balancer Listener is using at least TLS v1.2
## Severity
**HIGH** (score: 7.0/10)

Allowing a load balancer listener to negotiate below TLS 1.2 permits use of deprecated, weaker cipher suites/protocols, exposing data in transit to downgrade and interception attacks.

## Summary
This check ensures that ALB/NLB listeners configured for TLS/HTTPS termination use a security policy that enforces TLS 1.2 or higher, rather than allowing older, weaker protocol versions.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::ElasticLoadBalancingV2::Listener` resources.
- **Terraform**: `aws_lb_listener` and `aws_alb_listener` resources (evaluated via a graph-based policy that also inspects connected `aws_lb` resources for Gateway Load Balancer type).

## Why it matters
Older TLS versions (TLS 1.0, TLS 1.1) and their predecessor SSL protocols have known cryptographic weaknesses (e.g. BEAST, POODLE-adjacent issues, weak cipher suite support) and are explicitly disallowed by modern compliance standards such as PCI-DSS 3.2+, which mandates TLS 1.2 or higher for any protection of cardholder data in transit. A load balancer listener configured with a legacy SSL security policy will negotiate down to weaker protocol/cipher combinations if a client (or an attacker performing a downgrade attack) requests them, exposing session data to interception or decryption. Enforcing a minimum of TLS 1.2 (or 1.3) at the load balancer closes this downgrade path and ensures all traffic reaching backend targets was encrypted with a protocol still considered secure by current standards.

## How Checkov evaluates this
- **CloudFormation** (Python check): only evaluated when `Properties.Protocol` is `HTTPS` (ALB) or `TLS` (NLB) — for `TCP`/`UDP`/`TCP_UDP` listeners the check auto-**PASSES** since TLS policy is not applicable. For HTTPS/TLS listeners, it requires `Properties.SslPolicy` to be a string starting with one of the accepted TLS-1.2+ policy prefixes (`ELBSecurityPolicy-FS-1-2`, `ELBSecurityPolicy-TLS-1-2`, `ELBSecurityPolicy-TLS13-1-2`, `ELBSecurityPolicy-TLS13-1-3` for HTTPS; a similar TLS-specific set for NLB `TLS` protocol) — matching **PASSES**, anything else **FAILS**. It also passes listeners that redirect to HTTPS via a `RedirectConfig` action.
- **Terraform** (graph-based JSON policy): passes if the listener protocol is `TCP`/`UDP`/`TCP_UDP`; or if protocol is `HTTPS`/`TLS` and `ssl_policy` starts with an accepted TLS-1.2+ prefix; or if the listener's `default_action.type` is `redirect` to `HTTPS`; or if the listener is attached to a Gateway Load Balancer (`aws_lb.load_balancer_type == "gateway"`), which doesn't use TLS termination the same way. All other combinations **FAIL**.

## Non-compliant example
```hcl
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"   # allows TLS 1.0
  certificate_arn   = aws_acm_certificate.app.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
```

## Remediated example
```hcl
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"   # enforces TLS 1.2+
  certificate_arn   = aws_acm_certificate.app.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
```

## Remediation steps
1. Change `ssl_policy` (Terraform) / `SslPolicy` (CloudFormation) to a policy prefixed `ELBSecurityPolicy-FS-1-2`, `ELBSecurityPolicy-TLS-1-2`, or one of the newer `ELBSecurityPolicy-TLS13-*` policies.
2. Prefer `ELBSecurityPolicy-TLS13-1-2-2021-06` or later, which supports TLS 1.3 while maintaining TLS 1.2 backward compatibility and forward-secrecy cipher suites.
3. For HTTP listeners intended purely as a redirect surface, ensure the `default_action` is a `redirect` to `HTTPS` (this satisfies the check without needing an SslPolicy on the HTTP listener itself).
4. Test client compatibility after tightening the policy — very old clients that only support TLS 1.0/1.1 will no longer be able to connect.
5. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ALBListenerTLS12.py)
- [Checkov check source (Terraform graph check)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/AppLoadBalancerTLS12.json)
- [AWS ELB: Security policies for HTTPS/TLS listeners](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html)
