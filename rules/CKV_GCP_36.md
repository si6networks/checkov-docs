# CKV_GCP_36: Ensure that IP forwarding is not enabled on Instances

## Severity
**HIGH** (score: 7.0/10)

Enabling IP forwarding lets an instance route or spoof traffic on behalf of other hosts, which can be abused to bypass network segmentation and firewall assumptions or turn a compromised VM into a network pivot/proxy.

## Summary
This check fails when a GCE instance sets `can_ip_forward = true`, allowing it to send and receive packets with source/destination IPs other than its own assigned addresses.

## Applicability
Terraform only. Applies to `google_compute_instance`, `google_compute_instance_from_template`, and `google_compute_instance_template`.

## Why it matters
By default, GCP performs strict source/destination IP verification on packets to/from a VM's network interface, dropping traffic that doesn't match the instance's own IP — a built-in anti-spoofing and routing-integrity control. Enabling `can_ip_forward` disables this check, allowing the instance to act as a router, NAT gateway, or VPN endpoint, forwarding traffic on behalf of other IPs. If such an instance is compromised, an attacker can use it to route traffic in/out of the VPC bypassing intended network segmentation, spoof source addresses for other hosts, or pivot into subnets the instance wasn't otherwise a gateway for. Because this is an instance-level flag rather than a firewall rule, it can silently turn a single compromised VM into a network-wide pivot point that other controls (VPC firewalls scoped to expected traffic patterns) don't anticipate.

## How Checkov evaluates this
The check inspects `can_ip_forward`:
- **FAIL** if `can_ip_forward = true`.
- **PASS** if absent or `false`.
- Instances whose `name` starts with `gke-` are excluded from evaluation and automatically **PASS** (GKE nodes routinely require IP forwarding for pod networking).
- For `google_compute_instance_from_template`: **UNKNOWN** if `can_ip_forward` is not set on the instance and would come from the referenced template.

## Non-compliant example
```hcl
resource "google_compute_instance" "relay" {
  name           = "network-relay"
  machine_type   = "e2-small"
  zone           = "us-central1-a"
  can_ip_forward = true

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }
}
```

## Remediated example
```hcl
resource "google_compute_instance" "relay" {
  name           = "network-relay"
  machine_type   = "e2-small"
  zone           = "us-central1-a"
  can_ip_forward = false

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }
}
```

## Remediation steps
1. Remove `can_ip_forward = true` (or set it to `false`) unless the instance is a legitimate router/NAT/VPN gateway/relay by design.
2. For genuine routing appliances (NAT gateways, VPN relays like Tailscale subnet routers — which is why our repo has an intentional finding here), keep IP forwarding enabled but compensate with tight firewall rules limiting exactly which subnets/ports it may forward, dedicated service-account scoping, and network tagging so the exception is auditable and isolated.
3. If flagged instances are legitimately relays (e.g., our `tailscale-relay-gcp` module), add a Checkov skip comment (`checkov:skip=CKV_GCP_36:<justification>`) directly above the resource so the suppression is documented and reviewable, rather than leaving an unexplained finding.
4. Changing `can_ip_forward` on an existing instance requires the instance to be stopped; Terraform will show this as a required stop/start or, on some provider versions, a full replacement — plan for brief downtime.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeIPForward.py)
- [GCP: Enabling IP forwarding for instances](https://cloud.google.com/vpc/docs/using-routes#canipforward)
