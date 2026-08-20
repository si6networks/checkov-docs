# CKV_GCP_77: Ensure Google compute firewall ingress does not allow unrestricted access on the FTP-data port
## Severity
**HIGH** (score: 7.0/10)

Unrestricted 0.0.0.0/0 ingress to the FTP data port exposes unencrypted file transfer contents to internet-wide interception, though it lacks the direct credential exposure of the FTP control port.

## Summary
This check ensures a `google_compute_firewall` ingress rule does not allow unrestricted (`0.0.0.0/0`) access to TCP port 20, the FTP data transfer port.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_compute_firewall`

## Why it matters
Port 20 is used by FTP for the actual data channel (in active mode), working alongside the control channel on port 21. Like FTP control traffic, FTP data transfer is unencrypted by default, so opening it to the entire internet exposes transferred file contents (and, in active-mode setups, additional session metadata) to interception, and broadens the attack surface for any vulnerabilities in FTP server/data-channel handling. Firewalls should scope this port to specific known source ranges rather than the whole internet, and ideally FTP itself should be replaced with an encrypted transfer protocol.

## How Checkov evaluates this
This check subclasses the shared `AbsGoogleComputeFirewallUnrestrictedIngress` base logic, parameterized with `PORT = 20`. It inspects the firewall's `allow` blocks for a rule permitting port 20 (directly or via a range) and checks whether `source_ranges` includes `0.0.0.0/0`. If port 20 is allowed from unrestricted source ranges, the check FAILS; if the source ranges are scoped to specific CIDRs (or port 20 is not allowed at all), it PASSES.

## Non-compliant example
```hcl
resource "google_compute_firewall" "allow_ftp_data" {
  name    = "allow-ftp-data"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["20"]
  }

  source_ranges = ["0.0.0.0/0"]
  direction     = "INGRESS"
}
```

## Remediated example
```hcl
resource "google_compute_firewall" "allow_ftp_data" {
  name    = "allow-ftp-data"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["20"]
  }

  source_ranges = ["10.20.0.0/24"]  # restricted to a known internal range
  direction     = "INGRESS"
}
```

## Remediation steps
1. Find firewall rules allowing TCP port 20 (or a range including it) with `source_ranges` containing `0.0.0.0/0`.
2. Restrict `source_ranges` to the specific CIDR blocks that require FTP data-channel access.
3. Prefer passive-mode FTP with a scoped ephemeral port range plus SFTP/FTPS, or migrate off FTP entirely, rather than leaving the active-mode data port open to the internet.
4. Remove the firewall rule entirely if the FTP data channel is not actually needed (e.g., if only passive-mode or SFTP is in use).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeFirewallUnrestrictedIngress20.py)
- [Google Cloud: VPC firewall rules overview](https://cloud.google.com/firewall/docs/firewalls)
