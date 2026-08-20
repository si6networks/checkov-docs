# CKV2_AWS_74: Ensure AWS Load Balancers use strong ciphers

## Severity
**LOW** (score: 2.0/10)

A weak or missing TLS cipher/protocol policy on a load balancer listener allows downgrade and man-in-the-middle attacks that can expose data in transit for internet-facing services.

## Summary
This check ensures that AWS Application/Network/Classic Load Balancer listeners terminate TLS with a strong, modern SSL security policy rather than using outdated or no security policy at all.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (implemented as a Checkov graph-based check, not a per-resource Python check).
- **Resource types:** `aws_alb_listener`, `aws_lb_listener`.

## Why it matters
Load balancer listeners that terminate HTTPS/TLS traffic negotiate a cipher suite and TLS protocol version with clients based on the attached SSL security policy (`ssl_policy`). Older or misconfigured security policies (e.g. `ELBSecurityPolicy-2015-05`, `ELBSecurityPolicy-TLS-1-0-2015-04`) permit legacy protocols such as TLS 1.0/1.1 and weak cipher suites (e.g. RC4, 3DES, ciphers without forward secrecy). These are vulnerable to known attacks (BEAST, POODLE, Sweet32) and no longer meet PCI-DSS, HIPAA, or NIST guidance, which mandate TLS 1.2+ with strong ciphers. A listener using a weak policy — or a listener that isn't actually using HTTPS/TLS as its protocol at all — exposes data in transit to downgrade and interception attacks.

## How Checkov evaluates this
This is a Terraform graph check (`LBWeakCiphers.json`). It flags a listener as **failing** if either condition is true:
1. The listener's `protocol` attribute is **not** `HTTPS` or `TLS` (i.e., it's plaintext HTTP/TCP, so no cipher policy applies but the connection also isn't encrypted) — actually, this branch flags any listener whose protocol isn't `HTTPS`/`TLS`.
2. The listener has an `ssl_policy` attribute set, but its value is **not** one of a fixed allow-list of legacy-but-checkov-approved policies: `ELBSecurityPolicy-2016-08`, `ELBSecurityPolicy-2015-05`, `ELBSecurityPolicy-TLS-1-0-2015-04`, `ELBSecurityPolicy-TLS-1-1-2017-01`, `ELBSecurityPolicy-2015-03`, `ELBSecurityPolicy-2015-02`, `ELBSecurityPolicy-2014-10`, `ELBSecurityPolicy-Default`, `ELBSecurityPolicy-2014-01`.

In other words, PASS requires the listener to use protocol `HTTPS` or `TLS` with an `ssl_policy` drawn from that known list (any policy not in the list — including newer, stronger ones like `ELBSecurityPolicy-TLS13-1-2-2021-06` or FS-variant policies — is treated as non-compliant by this specific list-based check, so review the intent against your organization's actual TLS requirements).

## Non-compliant example
```hcl
resource "aws_lb_listener" "bad" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08-Legacy"  # not in the approved list

  certificate_arn = aws_acm_certificate.cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}
```

## Remediated example
```hcl
resource "aws_lb_listener" "good" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"  # in the approved list

  certificate_arn = aws_acm_certificate.cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}
```

## Remediation steps
1. Ensure every listener that terminates TLS uses `protocol = "HTTPS"` (ALB) or `"TLS"` (NLB) — never plaintext for internet-facing or sensitive traffic.
2. Set `ssl_policy` explicitly to one of the values Checkov recognizes, e.g. `ELBSecurityPolicy-2016-08`.
3. In practice, prefer the strongest policy your clients support: AWS also publishes newer FS/TLS1.3 policies (e.g. `ELBSecurityPolicy-TLS13-1-2-2021-06`); if you use one of these, Checkov's fixed allow-list will still flag it as non-compliant even though it is more secure — treat this as a known limitation of the check and document the suppression (`checkov:skip=CKV2_AWS_74`) if your policy is intentionally newer than the list.
4. Re-plan/apply — changing `ssl_policy` on an existing listener does not require replacement, only an in-place update.
5. Periodically review AWS's list of predefined security policies and rotate away from deprecated ones (e.g. any policy still allowing TLS 1.0/1.1).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/LBWeakCiphers.json)
- [AWS: Security policies for Application Load Balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html)
