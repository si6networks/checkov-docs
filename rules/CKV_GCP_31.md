# CKV_GCP_31: Ensure that instances are not configured to use the default service account with full access to all Cloud APIs

## Severity
**MEDIUM** (score: 5.0/10)

The default Compute Engine service account carries the broad project-wide Editor role by default, so an instance using it exposes any compromise of that VM (e.g. via SSRF or app-level RCE) to a wide range of Cloud APIs, enabling lateral movement and privilege escalation across the project.

## Summary
This check fails when a GCE instance (or instance template) uses the project's default Compute Engine service account together with the broad `cloud-platform` OAuth scope, which effectively grants the VM's workload full access to every Google Cloud API the project's IAM policy allows.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to resource types `google_compute_instance`, `google_compute_instance_from_template`, and `google_compute_instance_template`.

## Why it matters
The default Compute Engine service account (`PROJECT_NUMBER-compute@developer.gserviceaccount.com`) is provisioned automatically and is often over-permissioned in older or loosely governed projects. When a VM is attached to this account *and* granted the `https://www.googleapis.com/auth/cloud-platform` scope (or the shorthand `cloud-platform`), any process or attacker who compromises the instance — via a vulnerable web app, SSRF against the metadata server, a malicious container, or a leaked SSH key — can call the instance metadata server to mint access tokens scoped to essentially all Cloud APIs (Storage, IAM, Compute, BigQuery, Secret Manager, etc.), constrained only by whatever IAM roles happen to be bound to that service account at the project level. Because the scope is set at the instance level, it silently widens the effective blast radius regardless of the account's actual IAM bindings, making it a classic privilege-escalation and lateral-movement vector in GCP compromises.

## How Checkov evaluates this
The check inspects the `service_account` block on the resource:
- If `service_account.email` matches the default service account pattern `\d+-compute@developer\.gserviceaccount\.com`, AND the `scopes` list contains `cloud-platform` (either the full URL or the short alias) → **FAIL**.
- If no `email` is given but `scopes` still contains `cloud-platform`/the full-access URL → **FAIL** (a missing email on `google_compute_instance` implies the default service account is used).
- Resources whose `name` starts with `gke-` are treated as GKE-managed node instances and automatically **PASS** (out of scope of user-authored config).
- For `google_compute_instance_from_template`, if `service_account` is absent while `source_instance_template` is set, the result is **UNKNOWN** because the effective scopes depend on the referenced template.
- Otherwise the resource **PASSES**.

## Non-compliant example
```hcl
resource "google_compute_instance" "app" {
  name         = "app-server"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }

  service_account {
    # email omitted -> defaults to the project's default compute service account
    scopes = ["cloud-platform"]
  }
}
```

## Remediated example
```hcl
resource "google_service_account" "app_sa" {
  account_id   = "app-server-sa"
  display_name = "App Server minimal-scope SA"
}

resource "google_compute_instance" "app" {
  name         = "app-server"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }

  service_account {
    email  = google_service_account.app_sa.email
    scopes = ["https://www.googleapis.com/auth/logging.write",
              "https://www.googleapis.com/auth/monitoring.write"]
  }
}
```

## Remediation steps
1. Create a purpose-built service account for the workload (`google_service_account`) instead of relying on the default compute SA.
2. Grant that service account only the minimum IAM roles it needs at the project/resource level (least privilege), rather than broad `roles/editor` or `roles/owner`.
3. Set narrowly scoped OAuth `scopes` on the instance (e.g., `logging.write`, `monitoring.write`) instead of `cloud-platform`; IAM roles bound to the SA — not instance scopes — should be the primary access boundary.
4. If `cloud-platform` scope is genuinely required, at minimum stop using the default compute service account so its permissions can be tightly scoped and audited independently of other workloads sharing the default SA.
5. For instances created from a template (`google_compute_instance_from_template`), verify and fix the scope/account configuration in the referenced `google_compute_instance_template`, since Checkov cannot evaluate it transitively.
6. Note: changing `service_account` on an existing `google_compute_instance` requires the instance to be stopped and typically forces recreation of the service_account block in-place (Terraform can update it without full replacement, but the instance must be stopped first).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeDefaultServiceAccountFullAccess.py)
- [GCP: Access scopes](https://cloud.google.com/compute/docs/access/service-accounts#accesscopesiam)
