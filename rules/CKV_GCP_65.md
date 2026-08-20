# CKV_GCP_65: Manage Kubernetes RBAC users with Google Groups for GKE
## Severity
**LOW** (score: 2.0/10)

Missing Google-Groups-based RBAC is an access-governance gap (stale per-user bindings can persist after offboarding) rather than a directly exploitable misconfiguration.

## Summary
This check ensures a GKE cluster is configured to bind Kubernetes RBAC authorization to Google Groups (via the GKE "Google Groups for RBAC" feature) rather than relying purely on individual IAM bindings.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`

## Why it matters
Without Google Groups–based RBAC, GKE cluster access control has to be managed one Kubernetes `RoleBinding`/`ClusterRoleBinding` at a time, per individual user. This is operationally fragile: as team membership changes (onboarding, offboarding, role changes), administrators must remember to update Kubernetes-native bindings separately from the organization's identity source of truth. In practice this drift leads to stale access — former employees or contractors retaining cluster permissions long after they should have been revoked, because nobody remembered to delete a `RoleBinding`. Enabling `authenticator_groups_config` lets the cluster resolve RBAC subjects against a Google Group, so access can be centrally managed in Google Workspace/Cloud Identity and automatically reflects group membership changes, closing this offboarding gap.

## How Checkov evaluates this
Checkov inspects the `google_container_cluster` resource block for the attribute path `authenticator_groups_config[0].security_group`. Any non-empty value (the check uses `ANY_VALUE`, meaning any value at all satisfies it) causes a PASS; if the block or attribute is absent, the check FAILS.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  # No authenticator_groups_config block defined
  initial_node_count = 1
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  authenticator_groups_config {
    security_group = "gke-security-groups@example.com"
  }

  initial_node_count = 1
}
```

## Remediation steps
1. Create (or identify) a Google Group named exactly `gke-security-groups@<your-domain>` — GKE requires this specific naming convention for the top-level security group.
2. Add the appropriate admin/security groups as members of `gke-security-groups@<your-domain>` (nested groups are supported).
3. Add an `authenticator_groups_config { security_group = "gke-security-groups@<your-domain>" }` block to each `google_container_cluster` resource.
4. Apply Kubernetes `RoleBinding`/`ClusterRoleBinding` objects that reference `kind: Group` with the group email as the `name`, rather than binding individual user accounts.
5. Note: this feature requires Google Workspace or Cloud Identity; it cannot be enabled with a plain Gmail-only Google Cloud organization. Enabling it on an existing cluster may require the cluster to have the necessary IAM permissions granted to the GKE service account to read group membership.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEKubernetesRBACGoogleGroups.py)
- [Google Cloud: Google Groups for RBAC](https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control#google-groups-for-rbac)
