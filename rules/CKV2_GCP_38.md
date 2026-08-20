# CKV2_GCP_38: Ensure GCP compute global forwarding rule does not use HTTP proxies with EXTERNAL load balancing scheme

## Severity
**MEDIUM** (score: 5.0/10)

Same as the regional variant: an externally-facing global forwarding rule pointed at an HTTP (non-TLS) proxy exposes application traffic to eavesdropping/tampering on the public internet.

## Summary
This check flags global forwarding rules that point at an HTTP (not HTTPS) target proxy while using an `EXTERNAL` load-balancing scheme, since that configuration exposes a global load balancer's plaintext HTTP listener to the public internet.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_compute_global_forwarding_rule`

This is a graph-based check (Checkov "graph check", defined as JSON) rather than a Python check. It is the global-load-balancer counterpart to CKV2_GCP_37 (regional forwarding rules).

## Why it matters
A global external forwarding rule pointed at a `google_compute_target_http_proxy` (plain HTTP) with `load_balancing_scheme = EXTERNAL` serves internet-facing traffic without TLS. Because this is a *global* forwarding rule, the exposure spans Google's global anycast frontend, meaning the plaintext endpoint is reachable from virtually any point on the internet at scale. Attackers on the network path (public Wi-Fi, malicious ISPs, compromised routers) can eavesdrop on or tamper with all requests and responses — including credentials, cookies, and API keys — undermining confidentiality and integrity guarantees that users expect from a production-facing load balancer.

## How Checkov evaluates this
The check passes if **either** of these OR-branches is true:
1. The `target` attribute of the `google_compute_global_forwarding_rule` does **not** reference `google_compute_region_target_http_proxy` and does not contain the literal string `targetHttpProxies` — meaning it isn't pointing at an HTTP proxy.
2. OR the `load_balancing_scheme` attribute exists and is **not** (case-insensitively) `EXTERNAL`.

The check **fails** only when the global forwarding rule targets an HTTP proxy AND uses the `EXTERNAL` load balancing scheme.

## Non-compliant example
```hcl
resource "google_compute_target_http_proxy" "default" {
  name    = "global-http-proxy"
  url_map = google_compute_url_map.default.id
}

resource "google_compute_global_forwarding_rule" "insecure" {
  name                  = "global-fr"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "80"
  target                = google_compute_target_http_proxy.default.id
  ip_address            = google_compute_global_address.default.address
}
```

## Remediated example
```hcl
resource "google_compute_target_https_proxy" "default" {
  name             = "global-https-proxy"
  url_map          = google_compute_url_map.default.id
  ssl_certificates = [google_compute_managed_ssl_certificate.default.id]
}

resource "google_compute_global_forwarding_rule" "secure" {
  name                  = "global-fr"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  target                = google_compute_target_https_proxy.default.id
  ip_address            = google_compute_global_address.default.address
}
```

## Remediation steps
1. Replace `google_compute_target_http_proxy` with `google_compute_target_https_proxy`, attaching a Google-managed or self-managed SSL certificate.
2. Update the global forwarding rule's `target` to reference the HTTPS proxy and change `port_range` to `443`.
3. If an HTTP listener must remain (e.g., to redirect to HTTPS), configure the URL map behind the HTTP proxy to issue a permanent redirect rather than serving content directly.
4. Prefer `google_compute_managed_ssl_certificate` for automatic renewal and to avoid certificate-expiry outages.
5. Apply with `terraform plan`/`apply` — proxy/target changes can require rule replacement, so schedule around a low-traffic window if the LB is production-facing.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPComputeGlobalForwardingRuleCheck.json
- Google Cloud docs: https://cloud.google.com/load-balancing/docs/https
