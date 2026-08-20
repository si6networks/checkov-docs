# CKV2_GCP_18: Ensure GCP network defines a firewall and does not use the default firewall
## Severity
**HIGH** (score: 7.5/10)

Relying on GCP's implicit default network means the auto-created default firewall rules apply, which include overly permissive rules such as allowing SSH and internal traffic from broad source ranges instead of an explicitly reviewed, least-privilege firewall configuration.

## Summary
This check ensures that every `google_compute_network` (VPC) defined in Terraform has at least one explicit `google_compute_firewall` resource connected to it, rather than relying on GCP's implicit/legacy default firewall behavior.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform, specifically the `google_compute_network` resource, evaluated for a graph connection to `google_compute_firewall` resources.

## Why it matters
A "default" (auto-mode) GCP VPC network historically ships with permissive default firewall rules (e.g. allowing internal traffic broadly and, in the classic default network, allowing SSH/RDP/ICMP from `0.0.0.0/0`). Defining a custom VPC without any explicit firewall rules means the network's access control posture is left to implicit defaults rather than an intentional, reviewed configuration — which is both an availability risk (nothing is actually reachable in some configurations, or conversely everything is too open depending on the default) and a security risk (undocumented, un-reviewed rules governing what's exposed). Because this finding is in an *external module* your code vendors in (`terraform-google-network`), it's a strong signal that the VPC module is being consumed without the caller supplying any firewall rules — meaning the network's actual ingress/egress policy is undefined or inherited implicitly rather than explicitly declared and version-controlled, undermining the "infrastructure as code" guarantee that the Terraform accurately describes network access.

## How Checkov evaluates this
An `and` of two graph conditions:
1. A `filter` restricting evaluation to resources of type `google_compute_network`.
2. A `connection` condition requiring that a `google_compute_network` resource **has** (`exists`) at least one connected `google_compute_firewall` resource.

FAIL when a `google_compute_network` resource exists in the Terraform graph with no `google_compute_firewall` resource referencing/connected to it (e.g. no firewall rule sets `network = google_compute_network.this.id` or `self_link`).

## Non-compliant example
```hcl
resource "google_compute_network" "vpc" {
  name                    = "app-vpc"
  auto_create_subnetworks = false
}
# No google_compute_firewall resource references this network anywhere
```

## Remediated example
```hcl
resource "google_compute_network" "vpc" {
  name                    = "app-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_firewall" "allow_internal" {
  name    = "app-vpc-allow-internal"
  network = google_compute_network.vpc.self_link

  direction     = "INGRESS"
  source_ranges = ["10.0.0.0/8"]

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }
}

resource "google_compute_firewall" "deny_all_ingress" {
  name    = "app-vpc-deny-all-ingress"
  network = google_compute_network.vpc.self_link

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  priority      = 65534

  deny {
    protocol = "all"
  }
}
```

## Remediation steps
1. For every `google_compute_network`, define at least one explicit `google_compute_firewall` resource (referencing the network via `network = google_compute_network.<name>.self_link` or `.id`) so access control is intentional and version-controlled rather than left to implicit defaults.
2. Add an explicit default-deny ingress rule (lowest priority) plus narrowly scoped allow rules for required traffic (see CKV2_GCP_12 for guidance on avoiding overly permissive allow-all rules).
3. Because the affected resource is in a vendored external module (`terraform-google-network`), pass firewall rule inputs through that module's variables (most versions of `terraform-google-network` expose a companion firewall submodule or `firewall_rules` variable) rather than modifying the vendored code directly.
4. Re-run Checkov / `terraform plan` after adding firewall rules to confirm the finding clears.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPNetworkDoesNotUseDefaultFirewall.json
- GCP docs: https://cloud.google.com/firewall/docs/firewalls
