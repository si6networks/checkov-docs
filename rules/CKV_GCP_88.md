# CKV_GCP_88: Ensure Google compute firewall ingress does not allow unrestricted mysql access
## Severity
**CRITICAL** (score: 9.0/10)

This detects a firewall rule allowing unrestricted (0.0.0.0/0) ingress to MySQL port 3306, directly exposing a database service to the entire internet for potential brute-force or exploitation attacks.

## Summary
This check flags `google_compute_firewall` resources whose ingress `allow` rules permit unrestricted (`0.0.0.0/0`) source ranges on TCP port 3306, the standard MySQL port.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_compute_firewall`
- **Check type:** resource (subclass of the shared `AbsGoogleComputeFirewallUnrestrictedIngress` base check, parameterized with port 3306)

## Why it matters
Port 3306 is the default listening port for MySQL/MariaDB. A firewall rule that allows ingress from `0.0.0.0/0` on this port exposes any backing MySQL service directly to the entire internet, making it a prime target for automated scanners running brute-force credential attacks, exploitation of known MySQL CVEs, or attempts to abuse default/weak credentials. Because database ports are rarely intended to be reached directly by end users (application tiers should mediate access), unrestricted ingress on 3306 almost always indicates a misconfiguration rather than an intentional public service, and it collapses network segmentation as a defense layer — meaning a single leaked or weak database credential becomes immediately exploitable from anywhere, rather than requiring the attacker to first gain a foothold inside the trusted network.

## How Checkov evaluates this
The shared base class `AbsGoogleComputeFirewallUnrestrictedIngress` (parameterized here with `PORT = 3306`) inspects each `google_compute_firewall` resource's `allow` blocks and `source_ranges`:
- It looks for an `allow` rule whose `protocol` is `tcp` (or `all`) and whose `ports` list includes port 3306 (or is empty/omitted, which Google Cloud treats as "all ports").
- It checks whether `source_ranges` includes `0.0.0.0/0` (or is left unset, which for ingress rules also defaults to all sources).
- **FAIL**: an ingress-`direction` firewall rule allows tcp/3306 (or all ports) from `0.0.0.0/0`.
- **PASS**: port 3306 is not covered by any unrestricted-source allow rule (e.g., `source_ranges` is restricted to specific CIDRs, or port 3306 is explicitly excluded/denied).

## Non-compliant example
```hcl
resource "google_compute_firewall" "allow_mysql" {
  name    = "allow-mysql"
  network = google_compute_network.default.name

  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["3306"]
  }

  source_ranges = ["0.0.0.0/0"]
}
```

## Remediated example
```hcl
resource "google_compute_firewall" "allow_mysql" {
  name    = "allow-mysql"
  network = google_compute_network.default.name

  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["3306"]
  }

  # Restrict to known application-tier subnet(s) instead of the whole internet
  source_ranges = ["10.0.1.0/24"]
}
```

## Remediation steps
1. Replace `0.0.0.0/0` in `source_ranges` with the specific CIDR range(s) of the trusted application/bastion tier that legitimately needs database access.
2. Prefer `source_tags` or `source_service_accounts` scoped to the application instances/service accounts over broad CIDR ranges where possible.
3. If the database should never be reached directly from outside the VPC, remove the rule (or restrict it to internal ranges only) and require access via a private Cloud SQL connection, VPC-internal client, or bastion/IAP tunnel.
4. If using Cloud SQL rather than a self-managed MySQL VM, prefer Private IP / Cloud SQL Auth Proxy instead of exposing a public IP + firewall rule combination altogether.
5. Re-run Checkov / `terraform plan` after the change to confirm no other rule (e.g., a broader "allow-all" rule) still exposes port 3306.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeFirewallUnrestrictedIngress3306.py
- GCP docs: https://cloud.google.com/vpc/docs/firewalls
