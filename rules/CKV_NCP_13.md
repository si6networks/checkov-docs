# CKV_NCP_13: Ensure LB Listener uses only secure protocols

## Severity
**HIGH** (score: 7.5/10)

A load balancer listener that isn't restricted to HTTPS/TLS with a minimum of TLS 1.2 permits traffic in transit to be sent unencrypted or over weak/deprecated TLS versions, exposing it to interception or downgrade attacks.

## Summary
This check ensures that Naver Cloud Platform (NCP) Load Balancer listeners (`ncloud_lb_listener`) use an encrypted protocol (`HTTPS` or `TLS`) and enforce a minimum TLS version of `TLSV12`, rather than plaintext protocols like `HTTP` or `TCP`.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_lb_listener`
- **Check type:** resource-configuration check (Python)

## Why it matters
A load balancer listener using plaintext `HTTP`/`TCP` transmits all client traffic — including session cookies, authentication tokens, form submissions, and any sensitive payload — unencrypted over the network. This makes it trivial for anyone with visibility into the network path (a malicious actor on a shared network, a compromised router, or a man-in-the-middle) to intercept, read, and even tamper with traffic before it ever reaches your application. Even when the listener is encrypted, allowing outdated TLS versions (TLS 1.0/1.1) exposes clients to protocol-level attacks like POODLE, BEAST, and downgrade attacks that these older versions are known to be vulnerable to, and generally fail modern compliance frameworks (PCI-DSS, for instance, requires TLS 1.2+). Enforcing `HTTPS`/`TLS` with a `TLSV12` minimum ensures encrypted-in-transit traffic using a protocol version without known critical weaknesses.

## How Checkov evaluates this
The check reads the `protocol` attribute of the `ncloud_lb_listener` resource:
- If `protocol` is `HTTP` or `TCP` (i.e., not in `('HTTPS', 'TLS')`), the check **FAILS**.
- If `protocol` is `HTTPS` or `TLS`, Checkov then checks the `tls_min_version_type` attribute:
  - If `tls_min_version_type` is missing, the check **FAILS**.
  - If `tls_min_version_type` is present but not equal to `TLSV12`, the check **FAILS**.
  - If `tls_min_version_type` equals `TLSV12`, the check **PASSES**.

## Non-compliant example
```hcl
resource "ncloud_lb_listener" "web_listener" {
  load_balancer_no = ncloud_lb.main.id
  protocol         = "HTTP"
  port             = 80
  target_group_no  = ncloud_lb_target_group.web.id
}
```

## Remediated example
```hcl
resource "ncloud_lb_listener" "web_listener" {
  load_balancer_no    = ncloud_lb.main.id
  protocol            = "HTTPS"
  port                = 443
  target_group_no     = ncloud_lb_target_group.web.id
  tls_min_version_type = "TLSV12"
  ssl_certificate_no  = ncloud_certificate.web.id
}
```

## Remediation steps
1. Change the listener `protocol` from `HTTP`/`TCP` to `HTTPS` or `TLS`.
2. Attach a valid TLS certificate (`ssl_certificate_no`) to the listener.
3. Set `tls_min_version_type = "TLSV12"` explicitly — do not rely on a provider default, since it may allow older, weaker versions.
4. Redirect any remaining plaintext HTTP listener (e.g. on port 80) to HTTPS rather than serving content directly over it, to preserve compatibility for clients that initially connect over HTTP.
5. Update client/consumer configurations that may hardcode the old `http://` endpoint.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/LBListenerUsesSecureProtocols.py)
- [Naver Cloud Terraform provider: ncloud_lb_listener](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/lb_listener)
