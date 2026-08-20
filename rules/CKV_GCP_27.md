# CKV_GCP_27: Ensure that the default network does not exist in a project
## Severity
**MEDIUM** (score: 5.5/10)

Auto-created default networks come with permissive default firewall rules and a flat, unreviewed network topology, increasing the chance of unintended broad access, but this is a defense-in-depth/hardening gap rather than a guaranteed public exposure.

## Summary
This check fails when a `google_project` resource does not explicitly set `auto_create_network = false`, meaning GCP will auto-create the legacy "default" VPC network for the project.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_project`
- **Check type:** resource

## Why it matters
GCP's auto-created "default" network ships with a set of permissive, well-known firewall rules (`default-allow-ssh`, `default-allow-rdp`, `default-allow-icmp`, `default-allow-internal`) that allow broad ingress (e.g., SSH/RDP from `0.0.0.0/0`) unless someone remembers to lock them down after project creation. Because every new project gets the same predictable network name and rule set, it is a well-known target: automated scanners and red-team tooling specifically check for un-hardened default networks in newly created GCP projects. Relying on manual cleanup after project creation is fragile — a single project provisioned without following the runbook silently reintroduces a broad-exposure network. Disabling auto-creation forces network topology to be deliberate and defined in IaC from day one.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the key `auto_create_network[0]` on `google_project`:
- **PASS** — `auto_create_network` is explicitly set to `false`.
- **FAIL** — `auto_create_network` is absent (defaults to `true` in the underlying API) or explicitly `true`.

## Non-compliant example
```hcl
resource "google_project" "app_project" {
  name       = "delivery-platform"
  project_id = "delivery-platform-prod"
  org_id     = "123456789012"
  # auto_create_network omitted -> defaults to true -> FAILS
}
```

## Remediated example
```hcl
resource "google_project" "app_project" {
  name                = "delivery-platform"
  project_id          = "delivery-platform-prod"
  org_id              = "123456789012"
  auto_create_network = false
}

resource "google_compute_network" "custom_vpc" {
  name                    = "delivery-platform-vpc"
  project                 = google_project.app_project.project_id
  auto_create_subnetworks = false
}
```

## Remediation steps
1. Add `auto_create_network = false` to every `google_project` resource.
2. Define your own `google_compute_network` (custom-mode VPC, `auto_create_subnetworks = false`) with explicit, minimal firewall rules instead of relying on GCP's default network and its permissive rules.
3. For existing projects that already have a default network, delete it (`gcloud compute networks delete default`) after migrating any resources off it — this is a destructive, high-impact operation, so plan a maintenance window and confirm nothing depends on the default network/subnets first.
4. Setting `auto_create_network` on an already-existing `google_project` resource in Terraform typically only affects future project creation — it does not retroactively delete an existing default network; explicit cleanup is required.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleProjectDefaultNetwork.py
- GCP docs: https://cloud.google.com/vpc/docs/vpc#default-network
