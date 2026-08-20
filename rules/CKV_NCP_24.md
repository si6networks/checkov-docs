# CKV_NCP_24: Ensure Load Balancer Listener Using HTTPS
## Severity
**HIGH** (score: 7.0/10)

A Load Balancer listener that does not use HTTPS transmits client traffic in plaintext, exposing it to interception and tampering in transit.

## Summary
This check requires that NCloud Load Balancer listeners (`ncloud_lb_listener`) use the `HTTPS` protocol rather than a plaintext protocol such as HTTP or TCP.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_lb_listener`
- **Check type:** resource (single attribute value check)

## Why it matters
A load balancer listener configured for plain HTTP (or plain TCP) forwards traffic without transport-layer encryption. Any data traversing that listener — including request/response bodies, cookies, session tokens, and authentication headers — is sent in cleartext and can be intercepted or modified by anyone able to observe or sit in the path of the traffic (e.g., on shared network infrastructure, compromised routers, or via ARP/DNS spoofing). This is especially significant for a load balancer sitting at the internet edge, since it is the first hop terminating traffic from external clients. Terminating TLS at the listener (HTTPS) ensures confidentiality and integrity of client traffic before it reaches backend servers.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` that inspects the `protocol` attribute of `ncloud_lb_listener`:
- **Expected value:** `"HTTPS"`.
- **PASS:** `protocol = "HTTPS"`.
- **FAIL:** `protocol` is set to anything else (e.g., `"HTTP"`, `"TCP"`, `"PROXY_TCP"`) or is missing.

## Non-compliant example
```hcl
resource "ncloud_lb" "example" {
  name         = "example-lb"
  network_type = "PUBLIC"
  type         = "APPLICATION"
}

resource "ncloud_lb_listener" "example" {
  load_balancer_no = ncloud_lb.example.load_balancer_no
  protocol         = "HTTP"
  port             = 80
  target_group_no  = ncloud_lb_target_group.example.target_group_no
}
```

## Remediated example
```hcl
resource "ncloud_lb" "example" {
  name         = "example-lb"
  network_type = "PUBLIC"
  type         = "APPLICATION"
}

resource "ncloud_lb_listener" "example" {
  load_balancer_no = ncloud_lb.example.load_balancer_no
  protocol         = "HTTPS"
  port             = 443
  ssl_certificate_no = ncloud_certificate.example.certificate_no
  target_group_no  = ncloud_lb_target_group.example.target_group_no
}
```

## Remediation steps
1. Change the listener's `protocol` argument to `"HTTPS"`.
2. Provision or reference a valid TLS certificate (via the NCP certificate manager) and set `ssl_certificate_no` accordingly — HTTPS listeners require a certificate to terminate TLS.
3. Update the listener `port` to the conventional HTTPS port (443) if it was previously using 80 for HTTP.
4. If HTTP is retained for redirect purposes, ensure it only performs a 301/302 redirect to the HTTPS listener rather than forwarding application traffic in the clear.
5. Verify downstream health checks and target group configuration still match after the protocol change, since some NCP configurations tie health check protocol to listener protocol.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/LBListenerUsingHTTPS.py)
