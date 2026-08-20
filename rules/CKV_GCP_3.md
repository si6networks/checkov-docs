# CKV_GCP_3: Ensure Google compute firewall ingress does not allow unrestricted rdp access
## Severity
**CRITICAL** (score: 9.3/10)

A firewall rule permitting unrestricted ingress on RDP (port 3389) from 0.0.0.0/0 exposes a remote administrative desktop interface to the entire internet, a well-known vector for brute-force and exploit-based compromise.

## Summary
This check fails when a `google_compute_firewall` resource has an `allow` ingress rule that permits TCP port 3389 (RDP) from an unrestricted source range (`0.0.0.0/0`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_compute_firewall`
- **Check type:** resource (implemented via the shared `AbsGoogleComputeFirewallUnrestrictedIngress` base class, parameterized with `PORT = 3389`)

## Why it matters
RDP (port 3389) is the standard remote-desktop protocol for Windows VMs and is, alongside SSH, one of the most attacked ports on the public internet — mass-scanned continuously by botnets and ransomware operators specifically looking for exposed RDP endpoints to brute-force. Publicly exposed RDP has been the initial access vector for numerous large-scale ransomware incidents (weak/reused credentials, exploitation of unpatched RDP vulnerabilities like BlueKeep). A `google_compute_firewall` rule allowing ingress on 3389 from `0.0.0.0/0` exposes every matching instance to this constant background attack traffic regardless of how strong the Windows account passwords are.

## How Checkov evaluates this
The shared base check (`AbsGoogleComputeFirewallUnrestrictedIngress`) inspects:
- `direction` (must be an ingress-applicable rule),
- `source_ranges` for the presence of `0.0.0.0/0` (or equivalently unrestricted),
- `allow` blocks for whether port `3389` is included (explicit `ports = ["3389"]`, a port range containing it, or an "all ports" allow with no restriction).

- **FAIL** — the firewall allows ingress on port 3389 from `0.0.0.0/0`.
- **PASS** — port 3389 isn't opened, or is only reachable from restricted (non-`0.0.0.0/0`) source ranges, or it's a `deny` rule.

## Non-compliant example
```hcl
resource "google_compute_firewall" "allow_rdp_all" {
  name    = "allow-rdp-anywhere"
  network = google_compute_network.vpc.name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}
```

## Remediated example
```hcl
resource "google_compute_firewall" "allow_rdp_restricted" {
  name    = "allow-rdp-from-vpn"
  network = google_compute_network.vpc.name

  direction     = "INGRESS"
  source_ranges = ["203.0.113.0/24"]  # corporate VPN range only

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}
```

## Remediation steps
1. Replace `source_ranges = ["0.0.0.0/0"]` with the specific CIDR(s) of your VPN, bastion, or corporate network.
2. Preferably eliminate direct RDP exposure entirely by using **Identity-Aware Proxy (IAP) TCP forwarding** for RDP, restricting source ranges to Google's IAP CIDR `35.235.240.0/20` only, and requiring IAM-based access approval.
3. If broad RDP is unavoidable for legacy reasons, scope the rule with `target_tags`/`target_service_accounts` to only the specific instances that need it, and enforce MFA/strong password policy on the Windows side as compensating controls.
4. This is a metadata-only firewall-rule change with no instance downtime, but confirm no automation depends on the current open rule before tightening.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeFirewallUnrestrictedIngress3389.py
- GCP docs: https://cloud.google.com/iap/docs/using-tcp-forwarding
