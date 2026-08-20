# CKV2_GCP_37: Ensure GCP compute regional forwarding rule does not use HTTP proxies with EXTERNAL load balancing scheme

## Severity
**MEDIUM** (score: 5.0/10)

Pairing an HTTP (unencrypted) proxy target with an EXTERNAL load-balancing scheme exposes traffic to interception/tampering over the public internet, but it is a plaintext-transport weakness rather than a fully open admin surface or credential exposure.

## Summary
This check flags regional forwarding rules that point at an HTTP (not HTTPS) target proxy while using an `EXTERNAL` load-balancing scheme, since that configuration exposes a load balancer's plaintext HTTP listener to the public internet.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_compute_forwarding_rule`

This is a graph-based check (Checkov "graph check", defined as JSON) rather than a Python check.

## Why it matters
A regional external forwarding rule that targets a `google_compute_region_target_http_proxy` (plain HTTP, not HTTPS) serves traffic unencrypted over the public internet. Any client-to-load-balancer traffic — including cookies, authentication tokens, form submissions, and API payloads — can be intercepted or tampered with by a network-level attacker (e.g., on shared Wi-Fi, a compromised ISP, or via BGP hijacking). Combined with `load_balancing_scheme = EXTERNAL`, this means the insecure endpoint is reachable from anywhere, not just internally. This is a classic "downgrade to HTTP" misconfiguration that undermines TLS protections elsewhere in the stack and can enable credential theft, session hijacking, or man-in-the-middle content injection.

## How Checkov evaluates this
The check passes if **either** of these OR-branches is true:
1. The `target` attribute of the `google_compute_forwarding_rule` does **not** reference `google_compute_region_target_http_proxy` (Terraform resource reference) **and** does not contain the literal string `targetHttpProxies` (raw API path) — i.e., the rule is not pointing at an HTTP proxy at all (it might point to HTTPS, TCP, etc.).
2. OR the `load_balancing_scheme` attribute exists and is **not** (case-insensitively) equal to `EXTERNAL` — i.e., the scheme is `INTERNAL`, `INTERNAL_MANAGED`, `EXTERNAL_MANAGED`, etc., rather than a purely external classic scheme.

The check **fails** only when the forwarding rule targets an HTTP proxy AND its load balancing scheme is `EXTERNAL` (publicly reachable, plaintext).

## Non-compliant example
```hcl
resource "google_compute_region_target_http_proxy" "default" {
  name    = "region-http-proxy"
  region  = "us-central1"
  url_map = google_compute_region_url_map.default.id
}

resource "google_compute_forwarding_rule" "insecure" {
  name                  = "regional-fr"
  region                = "us-central1"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "80"
  target                = google_compute_region_target_http_proxy.default.id
}
```

## Remediated example
```hcl
resource "google_compute_region_target_https_proxy" "default" {
  name             = "region-https-proxy"
  region           = "us-central1"
  url_map          = google_compute_region_url_map.default.id
  ssl_certificates = [google_compute_region_ssl_certificate.default.id]
}

resource "google_compute_forwarding_rule" "secure" {
  name                  = "regional-fr"
  region                = "us-central1"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  target                = google_compute_region_target_https_proxy.default.id
}
```

## Remediation steps
1. Replace the `google_compute_region_target_http_proxy` with a `google_compute_region_target_https_proxy` and attach a valid SSL certificate (managed or self-managed).
2. Update the forwarding rule's `target` to reference the HTTPS proxy and change `port_range` to `443`.
3. If plain HTTP must remain reachable (e.g., for ACME HTTP-01 challenges or redirect-to-HTTPS only), change `load_balancing_scheme` to an internal scheme, or configure the HTTP listener solely to issue a 301 redirect to HTTPS via the URL map.
4. Consider using Google-managed SSL certificates (`google_compute_managed_ssl_certificate`) to simplify certificate lifecycle management.
5. Re-run `terraform plan` — changing the proxy/target may require replacing the forwarding rule.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPComputeRegionalForwardingRuleCheck.json
- Google Cloud docs: https://cloud.google.com/load-balancing/docs/https
