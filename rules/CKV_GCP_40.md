# CKV_GCP_40: Ensure that Compute instances do not have public IP addresses

## Severity
**HIGH** (score: 8.0/10)

A public IP address directly exposes the instance to the internet, expanding its attack surface to any of its listening services and making it a direct target for scanning and exploitation.

## Summary
This check fails when a GCE instance's `network_interface` block defines an `access_config` sub-block, which is what provisions an ephemeral or static external (public) IP address on the instance.

## Applicability
Terraform only. Applies to `google_compute_instance`, `google_compute_instance_template`, and `google_compute_instance_from_template`.

## Why it matters
Any instance with a public IP address is directly reachable from the internet, subject to continuous scanning and exploitation attempts against any exposed service, and it materially expands the attack surface regardless of firewall rules layered on top (firewall misconfigurations, forgotten open ports, or 0-day vulnerabilities in exposed services all become internet-exploitable rather than requiring an attacker to first pivot into the VPC). Best practice is to keep compute instances private, reaching the internet outbound (if needed) via Cloud NAT, and reaching them inbound (if needed) via a load balancer, bastion host, Identity-Aware Proxy (IAP) TCP forwarding, or a VPN/interconnect — all of which centralize and audit access rather than exposing the instance directly. Direct public IPs on individual VMs bypass these choke points and make consistent security policy enforcement (WAF, DDoS protection, centralized logging) much harder to guarantee.

## How Checkov evaluates this
The check treats presence of `network_interface[0].access_config` as forbidden (`ANY_VALUE` in the forbidden-values list):
- **FAIL** if `network_interface[0].access_config` is present at all (any value — even an empty block provisions an ephemeral external IP).
- **PASS** if `access_config` is absent (instance has only an internal IP).
- For `google_compute_instance_from_template`: **UNKNOWN** if `network_interface` is entirely absent, since the effective networking would come from the source template.

## Non-compliant example
```hcl
resource "google_compute_instance" "relay" {
  name         = "tailscale-relay"
  machine_type = "e2-small"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
    access_config {
      // Ephemeral public IP
    }
  }
}
```

## Remediated example
```hcl
resource "google_compute_instance" "relay" {
  name         = "tailscale-relay"
  machine_type = "e2-small"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
    // No access_config block -> internal IP only
  }
}

resource "google_compute_router_nat" "nat" {
  name                               = "relay-nat"
  router                             = google_compute_router.default.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}
```

## Remediation steps
1. Remove the `access_config` block from the instance's `network_interface` so it only has an internal IP.
2. If the instance needs outbound internet access (e.g., to reach package repositories), provision Cloud NAT (`google_compute_router_nat`) for the subnet instead of an external IP.
3. If the instance needs inbound access (e.g., SSH for admins), use Identity-Aware Proxy (IAP) TCP forwarding or a bastion host rather than a public IP.
4. For our repo's flagged case: a Tailscale relay/subnet router legitimately needs a public IP to accept incoming WireGuard connections from outside the VPC. If this is an intentional exception, add a documented `checkov:skip=CKV_GCP_40:<justification>` annotation rather than leaving an unexplained finding, and ensure the instance's firewall rules are tightly scoped to only the Tailscale UDP port.
5. Removing `access_config` from an existing instance can be done in-place (Terraform updates network_interface) but will change the instance's IP and may require updating DNS/firewall rules that reference the old public IP.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeExternalIP.py)
- [GCP: Cloud NAT overview](https://cloud.google.com/nat/docs/overview)
- [GCP: Identity-Aware Proxy for TCP forwarding](https://cloud.google.com/iap/docs/using-tcp-forwarding)
