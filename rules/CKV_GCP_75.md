# CKV_GCP_75: Ensure Google compute firewall ingress does not allow unrestricted FTP access
## Severity
**CRITICAL** (score: 9.0/10)

Unrestricted 0.0.0.0/0 ingress to the FTP control port exposes a cleartext-credential authentication service to the entire internet, enabling credential interception and brute-force/exploitation from any host.

## Summary
This check ensures a `google_compute_firewall` ingress rule does not allow unrestricted (`0.0.0.0/0`) access to TCP port 21, the FTP control port.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_compute_firewall`

## Why it matters
FTP (port 21) transmits authentication credentials and commands in cleartext by default, with no built-in encryption. Exposing it to the entire internet (`0.0.0.0/0`) makes any FTP service reachable to credential-stuffing and brute-force attacks, and any successful or intercepted session exposes plaintext credentials to network eavesdroppers. FTP servers have also historically been a frequent target for automated internet-wide scanning and exploitation of server software vulnerabilities. Firewalls should instead restrict ingress on this port to specific, known source IP ranges (e.g., a VPN, bastion, or corporate CIDR) or replace FTP with an encrypted alternative (SFTP/FTPS) entirely.

## How Checkov evaluates this
This check subclasses the shared `AbsGoogleComputeFirewallUnrestrictedIngress` base logic, parameterized with `PORT = 21`. It examines the firewall's `allow` blocks: for any `allow` entry whose `protocol` is `tcp`/`udp`/`all` (or otherwise matches) and whose `ports` list includes port 21 (either directly or via a range containing it), the check looks at `source_ranges`. If `source_ranges` includes `0.0.0.0/0` (i.e., unrestricted) for a rule permitting port 21, and the firewall is not a `deny` rule, the check FAILS. Restricting `source_ranges` to specific CIDRs, or not allowing port 21 at all, PASSES.

## Non-compliant example
```hcl
resource "google_compute_firewall" "allow_ftp" {
  name    = "allow-ftp"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["21"]
  }

  source_ranges = ["0.0.0.0/0"]
  direction     = "INGRESS"
}
```

## Remediated example
```hcl
resource "google_compute_firewall" "allow_ftp" {
  name    = "allow-ftp"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["21"]
  }

  source_ranges = ["10.20.0.0/24"]  # restricted to a known internal range
  direction     = "INGRESS"
}
```

## Remediation steps
1. Identify any firewall rules allowing TCP port 21 (or ranges including it) with `source_ranges` containing `0.0.0.0/0`.
2. Narrow `source_ranges` to only the specific CIDR blocks that legitimately need FTP access (VPN range, bastion host, partner IP block).
3. Where feasible, eliminate plaintext FTP entirely in favor of SFTP (port 22, via SSH) or FTPS, and remove the port-21 rule altogether.
4. If FTP must remain internet-facing for a legacy reason, layer additional controls: Cloud Armor, IP allowlisting, or a bastion/proxy in front of it.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeFirewallUnrestrictedIngress21.py)
- [Google Cloud: VPC firewall rules overview](https://cloud.google.com/firewall/docs/firewalls)
