# CKV_GCP_2: Ensure Google compute firewall ingress does not allow unrestricted ssh access
## Severity
**CRITICAL** (score: 9.3/10)

A firewall rule permitting unrestricted ingress on SSH (port 22) from 0.0.0.0/0 exposes a remote administrative shell interface to the entire internet, enabling brute-force or credential-based compromise of the host.

## Summary
This check fails when a `google_compute_firewall` resource has an `allow` ingress rule that permits TCP port 22 (SSH) from an unrestricted source range (`0.0.0.0/0`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_compute_firewall`
- **Check type:** resource (implemented via the shared `AbsGoogleComputeFirewallUnrestrictedIngress` base class, parameterized with `PORT = 22`)

## Why it matters
SSH (port 22) is the primary remote-administration protocol for Linux VMs, and it is one of the most heavily and continuously scanned/attacked ports on the internet. A firewall rule allowing ingress on TCP/22 from `0.0.0.0/0` exposes every matching instance to automated credential-stuffing and brute-force login attempts, exploitation of any unpatched SSH daemon vulnerability, and reconnaissance from bots operated by threat actors worldwide, 24/7. Because `google_compute_firewall` resources are network-wide and often apply broadly (default-tag or all-instance rules), a single overly permissive rule can expose an entire fleet rather than one machine. The standard mitigation is to restrict SSH ingress to known bastion/VPN/IAP ranges, or to use GCP Identity-Aware Proxy (IAP) TCP forwarding instead of exposing port 22 directly.

## How Checkov evaluates this
The base check (`AbsGoogleComputeFirewallUnrestrictedIngress`) inspects the firewall resource's:
- `direction` — only rules that are (implicitly or explicitly) `INGRESS` are relevant.
- `source_ranges` — checks whether `0.0.0.0/0` (or an equivalently unrestricted range) is present.
- `allow` blocks — checks whether any `allow.ports` entry includes port `22`, or the protocol/ports combination effectively opens that port (e.g., `protocol = "all"` with no port restriction, or an explicit `ports = ["22"]"`/range containing 22).

- **FAIL** — the firewall allows ingress on port 22 from `0.0.0.0/0` (or has no `source_ranges` restriction combined with an `allow` covering port 22).
- **PASS** — port 22 is not opened, or is only opened from restricted (non `0.0.0.0/0`) source ranges, or the rule is a `deny` rule.

## Non-compliant example
```hcl
resource "google_compute_firewall" "allow_ssh_all" {
  name    = "allow-ssh-anywhere"
  network = google_compute_network.vpc.name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
```

## Remediated example
```hcl
resource "google_compute_firewall" "allow_ssh_restricted" {
  name    = "allow-ssh-from-bastion"
  network = google_compute_network.vpc.name

  direction     = "INGRESS"
  source_ranges = ["203.0.113.10/32"]  # bastion / VPN egress only

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
```

## Remediation steps
1. Replace `source_ranges = ["0.0.0.0/0"]` with the specific CIDR(s) of your bastion host, VPN, or corporate egress IP.
2. Preferably, remove direct SSH exposure entirely and use **Identity-Aware Proxy (IAP) TCP forwarding** for SSH (`gcloud compute ssh --tunnel-through-iap`), restricting the firewall rule's source range to Google's IAP range `35.235.240.0/20` only.
3. If broad SSH access is truly required for legacy reasons, add `source_tags`/`target_tags` scoping so the rule applies only to intended instances, not the whole VPC.
4. This is a metadata-only firewall-rule change — no instance downtime, but verify existing SSH sessions/automation won't be locked out before applying.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeFirewallUnrestrictedIngress22.py
- GCP docs: https://cloud.google.com/iap/docs/using-tcp-forwarding
