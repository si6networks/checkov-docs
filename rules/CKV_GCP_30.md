# CKV_GCP_30: Ensure that instances are not configured to use the default service account
## Severity
**LOW** (score: 2.0/10)

Instances using the default Compute Engine service account inherit its broad project-wide Editor-like permissions, so a compromised instance can pivot into significant privilege escalation across the project rather than being scoped to least-privilege access.

## Summary
This check fails when a `google_compute_instance`, `google_compute_instance_from_template`, or `google_compute_instance_template` resource attaches the project's auto-created default Compute Engine service account (`<project-number>-compute@developer.gserviceaccount.com`) instead of a purpose-built one.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_compute_instance`, `google_compute_instance_from_template`, `google_compute_instance_template`
- **Check type:** resource

## Why it matters
GCP's default Compute Engine service account is historically granted the broad, legacy `Editor` role on the project (in many long-lived projects it still is, even though newer projects default to fewer scopes). Any VM that runs as this account inherits whatever roles that shared account has — meaning a compromise of one VM (via an application vulnerability, SSRF against the metadata server, or a leaked instance credential) can potentially grant the attacker Editor-level access across the entire project: reading/modifying nearly all resources, not just the ones that specific VM's workload actually needs. This violates least privilege and creates a single shared "blast radius" account across every instance using it — compromising the weakest instance compromises the access level of all of them. Using a dedicated, narrowly-scoped service account per workload limits what an attacker can do even after successful instance compromise.

## How Checkov evaluates this
The check inspects the `service_account` block's `email` attribute against the regex `\d+-compute@developer\.gserviceaccount\.com`:
- **PASS** — `service_account[0].email` is set and does **not** match the default-service-account pattern (i.e., a custom/dedicated service account email is used).
- **PASS** — the resource's `name` starts with `gke-` (GKE-managed node instances are exempted, since GKE manages their service account assignment through node pools, not the instance resource directly).
- **FAIL** — a `service_account` block exists with an `email` matching the default pattern.
- **UNKNOWN** — no `service_account` block is present at all (Checkov can't determine what account will actually be attached — GCP would fall back to the default account and project-level `Compute Engine default service account`, but the check treats an entirely absent block as indeterminate rather than an automatic fail).

## Non-compliant example
```hcl
resource "google_compute_instance" "web" {
  name         = "web-server"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
  }

  service_account {
    email  = "123456789012-compute@developer.gserviceaccount.com"
    scopes = ["cloud-platform"]
  }
}
```

## Remediated example
```hcl
resource "google_service_account" "web_sa" {
  account_id   = "web-server-sa"
  display_name = "Web server dedicated SA"
}

resource "google_compute_instance" "web" {
  name         = "web-server"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
  }

  service_account {
    email  = google_service_account.web_sa.email
    scopes = ["cloud-platform"]
  }
}
```

## Remediation steps
1. Create a dedicated `google_service_account` per instance/workload role (e.g., one per application tier), rather than reusing the default Compute Engine service account.
2. Grant that service account only the specific IAM roles the workload actually needs (least privilege) — avoid `roles/editor`.
3. Reference the dedicated account's `.email` in the `service_account.email` field of the instance/instance template.
4. Changing `service_account` on an existing `google_compute_instance` typically **requires stopping the instance** (Terraform will show it as requiring a stop/start, and in some cases recreation depending on other changed attributes) — plan a maintenance window.
5. GKE node instances (name prefixed `gke-`) are exempt from this check since node service accounts are configured at the node-pool/cluster level, not the instance resource — see CKV_GCP_30's sibling GKE-specific controls instead.
6. Also disable the legacy default service account's automatic `Editor` grant at the project/org level via organization policy (`iam.automaticIamGrantsForDefaultServiceAccounts`) as a broader guardrail.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeDefaultServiceAccount.py
- GCP docs: https://cloud.google.com/compute/docs/access/service-accounts#default_service_account
