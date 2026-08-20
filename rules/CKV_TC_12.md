# CKV_TC_12: Ensure Tencent Cloud CLBs use modern, encrypted protocols

## Severity
**HIGH** (score: 7.5/10)

Allowing outdated or unencrypted listener protocols exposes traffic in transit to interception and downgrade attacks, directly threatening the confidentiality and integrity of data passing through the load balancer.

## Summary
This check ensures that Tencent Cloud CLB (Cloud Load Balancer) listeners do not use unencrypted or legacy protocols (`TCP`, `UDP`, `HTTP`) that transmit traffic in plaintext.

## Applicability
Terraform, resource type `tencentcloud_clb_listener` (Tencent Cloud provider).

## Why it matters
Listeners using `HTTP`, plain `TCP`, or `UDP` transmit application traffic without transport-layer encryption, meaning anyone able to observe network traffic between the client and the load balancer — on a shared network segment, a compromised intermediate router, or via ARP/DNS spoofing on the local network — can read request and response contents in full, including session cookies, authentication headers, form data, and any other sensitive payload. This also enables trivial man-in-the-middle tampering: an attacker who can intercept unencrypted traffic can modify requests/responses in transit without either endpoint detecting it, unlike TLS-protected traffic where tampering breaks the integrity check. Using `HTTPS` or `TCP_SSL` protocols instead terminates (or passes through) TLS at the load balancer, ensuring confidentiality and integrity for traffic traversing the public network.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the `protocol` attribute of a `tencentcloud_clb_listener`. The forbidden values are `"TCP"`, `"UDP"`, and `"HTTP"` — if `protocol` is set to any of these, the check **FAILS**. Any other protocol value (e.g. `HTTPS`, `TCP_SSL`) causes the check to **PASS**.

## Non-compliant example
```hcl
resource "tencentcloud_clb_listener" "example" {
  clb_id        = tencentcloud_clb_instance.example.id
  port          = 80
  protocol      = "HTTP"
  listener_name = "web-http-listener"
}
```

## Remediated example
```hcl
resource "tencentcloud_clb_listener" "example" {
  clb_id            = tencentcloud_clb_instance.example.id
  port              = 443
  protocol          = "HTTPS"   # encrypted, TLS-terminated at the CLB
  listener_name     = "web-https-listener"
  certificate_ssl_mode = "UNIDIRECTIONAL"
  certificate_id    = tencentcloud_ssl_certificate.example.id
}
```

## Remediation steps
1. Change `protocol` from `TCP`/`UDP`/`HTTP` to `HTTPS` (for Layer 7 listeners) or `TCP_SSL` (for Layer 4 listeners needing TLS passthrough/termination).
2. Provision or import a TLS certificate (`tencentcloud_ssl_certificate`) and reference it via `certificate_id` on the listener.
3. Update the listener `port` to the appropriate encrypted-protocol port (typically 443) and update client/DNS configuration accordingly.
4. For UDP-based workloads that cannot use TLS at the transport layer (e.g. certain real-time protocols), evaluate whether DTLS or an application-layer encryption alternative is feasible; if truly unencryptable, document and isolate this listener as an explicit exception with compensating network controls.
5. Redirect any remaining plaintext HTTP listener to HTTPS rather than serving content over it, if backward compatibility is required during a migration period.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/CLBListenerProtocol.py
