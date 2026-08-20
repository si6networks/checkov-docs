# CKV2_GCP_2: Ensure legacy networks do not exist for a project
## Severity
**MEDIUM** (score: 5.0/10)

Legacy GCP networks lack subnetwork-based segmentation and predate current default-deny networking conventions, increasing the chance of unintentionally broad reachability between resources.

## Summary
This check ensures a GCP project does not use "legacy" VPC networks — networks configured without proper subnetwork auto-creation controls.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `google_compute_network` (evaluated in connection with `google_project`)

## Why it matters
GCP legacy networks are a deprecated networking mode that predates the current subnet-based VPC model. Legacy networks use a single, global IP range across all regions with no subnetwork boundaries, which removes the ability to apply per-region network segmentation, makes IP address planning inflexible, and is incompatible with many modern GCP networking features (e.g., VPC peering restrictions, Shared VPC advantages, many firewall/routing capabilities). From a security standpoint, the lack of subnet boundaries makes it harder to isolate workloads, apply least-privilege network segmentation, and reason about blast radius if a resource is compromised. Google has deprecated the creation of new legacy networks entirely, and any that persist represent technical debt with reduced security tooling support.

## How Checkov evaluates this
This is a Terraform graph-based (connection-aware) check. For a `google_project`, it inspects the connected `google_compute_network` resource(s):
- **PASS** if the `google_compute_network` is not connected to a `google_project` via `project_id` at all, **or**
- **PASS** if it is connected AND `auto_create_subnetworks` is absent (defaults to `true`, i.e., auto-mode/non-legacy) or explicitly `false` is NOT what triggers pass — actually the policy passes when `auto_create_subnetworks` does **not exist** (default `true`, standard subnet-mode network) OR when it is explicitly set to `false` (custom subnet mode, which still uses subnets, just not auto-created ones).
- **FAIL** case arises functionally when a legacy network configuration is detected — i.e. when the network is effectively operating without proper subnet definitions (the "legacy" mode, which Terraform models by *not* setting `auto_create_subnetworks` combined with no subnetworks defined, historically `auto_create_subnetworks = true` with no regions was the old legacy indicator). In practice: ensure every `google_compute_network` explicitly sets `auto_create_subnetworks` (to `true` for auto subnet mode, or `false` paired with explicit `google_compute_subnetwork` resources for custom subnet mode) rather than relying on ambiguous/legacy defaults.

## Non-compliant example
```hcl
resource "google_project" "my_project" {
  name       = "my-project"
  project_id = "my-project-id"
}

# Legacy-style network: no subnet mode declared, no subnetworks defined
resource "google_compute_network" "legacy_net" {
  name    = "legacy-network"
  project = google_project.my_project.project_id
}
```

## Remediated example
```hcl
resource "google_project" "my_project" {
  name       = "my-project"
  project_id = "my-project-id"
}

resource "google_compute_network" "vpc_net" {
  name                    = "custom-vpc-network"
  project                 = google_project.my_project.project_id
  auto_create_subnetworks = false   # explicit custom subnet mode
}

resource "google_compute_subnetwork" "subnet" {
  name          = "subnet-us-central1"
  network       = google_compute_network.vpc_net.id
  ip_cidr_range = "10.10.0.0/24"
  region        = "us-central1"
}
```

## Remediation steps
1. Inventory all VPC networks in the project (`gcloud compute networks list`) and identify any in legacy mode (`gcloud compute networks describe NETWORK --format="value(x_gcloud_mode)"` shows `legacy`).
2. For Terraform-managed networks, explicitly set `auto_create_subnetworks` on every `google_compute_network` resource rather than leaving it implicit.
3. Migrate legacy networks to custom-mode VPCs with explicit `google_compute_subnetwork` resources per region needed.
4. Migrating a legacy network to a subnet-mode network typically requires re-creating resources or careful use of `gcloud compute networks update <NAME> --switch-to-custom-subnet-mode` — plan for a maintenance window since this affects instance networking and can require re-attaching resources.
5. Google no longer allows creation of new legacy networks in most projects, so this mainly affects pre-existing infrastructure being migrated to IaC.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPProjectHasNoLegacyNetworks.json
- GCP docs: https://cloud.google.com/vpc/docs/legacy
