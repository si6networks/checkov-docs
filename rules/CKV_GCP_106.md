# CKV_GCP_106: Ensure Google compute firewall ingress does not allow unrestricted http port 80 access

## Severity
**HIGH** (score: 7.0/10)

Unrestricted ingress on port 80 exposes the associated service to unauthenticated, internet-wide traffic, a common entry point for scanning and exploitation of web-facing services.

## Summary
This check ensures that a `google_compute_firewall` ingress rule does not permit unrestricted (`0.0.0.0/0`) inbound access to TCP port 80 (HTTP).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework**: Terraform
- **Resource type**: `google_compute_firewall`
- Evaluates ingress rules (`direction = "INGRESS"` or default) with `allow` blocks and their `source_ranges`.

## Why it matters
Port 80 serves unencrypted HTTP traffic. A firewall rule that allows any source IP (`0.0.0.0/0`) to reach port 80 on backing instances creates the following risks:

- **Cleartext traffic exposure**: Any credentials, session tokens, or sensitive data transmitted over HTTP (rather than HTTPS) to the affected instances can be intercepted by anyone able to observe the network path, and the fact that the firewall allows it from any source means attackers do not even need to be on-path — they can connect directly.
- **Direct attack surface for web application vulnerabilities**: Opening port 80 from the entire internet exposes whatever HTTP service is listening (often intended for internal use, health checks, or admin panels) to internet-wide scanning and exploitation of any application-layer vulnerability.
- **Common precursor to broader compromise**: Internet-facing HTTP services with known CVEs, default credentials, or debug endpoints left enabled are one of the most frequently exploited initial access vectors in cloud environments; unrestricted ingress removes any network-layer barrier to reaching them.
- **Undermines a "HTTPS-only" security posture**: Organizations that intend for all public traffic to go through HTTPS (with TLS termination at a load balancer) inadvertently leave a plaintext side door open if instance-level firewall rules still allow direct, unrestricted port 80 access bypassing that load balancer.

Note: this check specifically targets **port 80**; a companion check (CKV_GCP_105 is for Data Fusion — the equivalent unrestricted-ingress check for port 22/SSH is a separate check ID) exists for other commonly-exploited ports.

## How Checkov evaluates this
This check (`GoogleComputeFirewallUnrestrictedIngress80`) is a thin subclass of a shared base class (`AbsGoogleComputeFirewallUnrestrictedIngress`) parameterized with `PORT = 80`. The shared logic:
- Inspects the firewall rule's `allow` blocks for a protocol/port match on TCP port 80 (as an exact port, within a port range, or "all ports" via `["0-65535"]`/no ports specified).
- Checks whether `source_ranges` includes `0.0.0.0/0` (or is otherwise unrestricted / defaults to it).
- **FAILS** if the rule allows port 80 from an unrestricted source range.
- **PASSES** if port 80 is not covered by the rule, or if the rule restricts `source_ranges` to specific, non-`0.0.0.0/0` CIDR blocks.

## Non-compliant example
```hcl
resource "google_compute_firewall" "allow_http" {
  name    = "allow-http"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = ["0.0.0.0/0"]
  direction     = "INGRESS"
}
```

## Remediated example
```hcl
resource "google_compute_firewall" "allow_http" {
  name    = "allow-http"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  # Restrict to the load balancer's health-check ranges instead of the whole internet
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  direction     = "INGRESS"
}
```

## Remediation steps
1. Identify `google_compute_firewall` rules that allow TCP port 80 with `source_ranges` containing `0.0.0.0/0` (or with `source_ranges` omitted where it defaults broadly).
2. Narrow `source_ranges` to only the specific ranges that legitimately need access — e.g., GCP's HTTP(S) Load Balancer / health-check ranges (`130.211.0.0/22`, `35.191.0.0/16`) if the instances sit behind a GCP load balancer, or specific corporate/VPN egress IPs for internal tools.
3. If public HTTP access is genuinely required (e.g., a public web server, though HTTPS is strongly preferred), consider terminating TLS at a Google Cloud Load Balancer or Cloud Armor-protected front end instead of exposing instance-level port 80 directly, and use the firewall rule only to allow the load balancer's ranges.
4. Where HTTP is only meant as a redirect-to-HTTPS listener, ensure that redirect logic exists and still scope the firewall rule as narrowly as operationally possible.
5. Apply and verify with `gcloud compute firewall-rules describe` that the effective source ranges no longer include `0.0.0.0/0` for port 80.
6. Re-scan with Checkov to confirm the rule passes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeFirewallUnrestrictedIngress80.py
- GCP VPC firewall rules documentation: https://cloud.google.com/firewall/docs/firewalls
