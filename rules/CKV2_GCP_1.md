# CKV2_GCP_1: Ensure GKE clusters are not running using the Compute Engine default service account
## Severity
**LOW** (score: 2.0/10)

GKE nodes running as the Compute Engine default service account carry the broad legacy project-level Editor role by default, so compromising any single pod or node can be leveraged to pivot into near-full control of the GCP project.

## Summary
This check ensures that GKE node pools/clusters are not left on the Compute Engine default service account, and that the project instead explicitly manages default service account creation via `google_project_default_service_accounts`.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform. It is a graph-based connection check that inspects `google_project_default_service_accounts` resources in relation to `google_container_node_pool` and `google_container_cluster` resources.

## Why it matters
The Compute Engine default service account is automatically created in every GCP project and, historically, is granted the broad `roles/editor` (Project Editor) role on the project. If GKE nodes run using this default service account (instead of a dedicated, least-privilege service account), any workload compromise on a node — a vulnerable pod, a container escape, a leaked node metadata token — grants the attacker Editor-level access to nearly every resource in the project: they could read/modify Cloud Storage buckets, other Compute instances, Cloud SQL databases, IAM bindings, and more, far beyond what the cluster's workloads should ever need. This dramatically increases the blast radius of a single container-level compromise into a project-wide breach. The check verifies that the project actively disables/manages the default service account privilege footprint (via `google_project_default_service_accounts`) rather than leaving GKE nodes to silently inherit that account and its broad permissions.

## How Checkov evaluates this
This is a graph connection check with an `and` of three conditions, evaluated against `google_project_default_service_accounts` resources:
1. There must be **no** connection from a `google_project_default_service_accounts` resource to a `google_container_node_pool` resource (`not_exists`).
2. There must be **no** connection from a `google_project_default_service_accounts` resource to a `google_container_cluster` resource (`not_exists`).
3. A `filter` restricting evaluation to resources of type `google_project_default_service_accounts`.

In effect, Checkov flags the case where a `google_project_default_service_accounts` resource is wired up (referenced/connected) to a GKE cluster or node pool definition — meaning the cluster's service account configuration is tied to (or dependent on) the default-service-account management resource rather than an explicit, dedicated service account. Configuring node pools with their own `service_account` attribute (not connected through the default-service-accounts resource) passes.

## Non-compliant example
```hcl
resource "google_project_default_service_accounts" "default" {
  project = "my-project"
  action  = "DEPRIVILEGE"
}

resource "google_container_cluster" "primary" {
  name     = "primary-cluster"
  location = "us-central1"

  node_config {
    # No explicit service_account -> relies on the default Compute Engine SA,
    # tied through the default_service_accounts resource above
    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}
```

## Remediated example
```hcl
resource "google_service_account" "gke_nodes" {
  account_id   = "gke-nodes-sa"
  display_name = "GKE Nodes least-privilege SA"
}

resource "google_project_iam_member" "gke_nodes_logging" {
  project = "my-project"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_project_iam_member" "gke_nodes_metrics" {
  project = "my-project"
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_container_cluster" "primary" {
  name     = "primary-cluster"
  location = "us-central1"

  node_config {
    service_account = google_service_account.gke_nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}
```

## Remediation steps
1. Create a dedicated `google_service_account` for GKE node pools with only the IAM roles the workloads actually need (typically `roles/logging.logWriter`, `roles/monitoring.metricWriter`, `roles/monitoring.viewer`, `roles/artifactregistry.reader`, and any workload-specific roles — never `roles/editor`).
2. Reference that dedicated service account explicitly in each `node_config.service_account` block (or `google_container_node_pool.node_config.service_account`).
3. Use `google_project_default_service_accounts` with `action = "DEPRIVILEGE"` or `"DISABLE"` at the project level to reduce the default SA's blast radius project-wide, independent of GKE resource definitions.
4. Consider Workload Identity Federation (GKE Workload Identity) so individual Kubernetes workloads get their own scoped GCP identities instead of relying on the node-level service account at all.
5. Note: changing a node pool's service account typically requires recreating the node pool (new node pool + drain old one), so plan for a rolling migration rather than an in-place update.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GKEClustersAreNotUsingDefaultServiceAccount.json
- GCP docs: https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa
