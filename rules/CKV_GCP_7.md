# CKV_GCP_7: Ensure Legacy Authorization is set to Disabled on Kubernetes Engine Clusters
## Severity
**LOW** (score: 2.0/10)

Legacy ABAC is a coarse, largely all-or-nothing authorization mode that bypasses RBAC's scoped permissions, so a single leaked credential or over-provisioned workload can gain near-cluster-wide access.

## Summary
This check ensures that GKE clusters do not have the legacy Attribute-Based Access Control (ABAC) authorizer enabled, forcing use of the more granular Kubernetes RBAC model instead.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`

## Why it matters
Legacy ABAC (`enable_legacy_abac`) is a coarse, largely all-or-nothing authorization mode predating Kubernetes RBAC. When enabled, it effectively grants broad API access to any authenticated user/service account (including the `system:unauthenticated` group under some configurations), bypassing the fine-grained, resource/verb-scoped permission model that RBAC provides. This means a credential leak or a workload with more access than intended can result in far greater blast radius — e.g., a Pod's service account token that would only be scoped to read one namespace's secrets under RBAC could instead read/modify almost anything in the cluster under ABAC. Modern clusters should rely exclusively on RBAC (and IAM for cluster-level operations), so leaving legacy ABAC enabled reintroduces a control that is both redundant and dangerously permissive.

## How Checkov evaluates this
Checkov reads the `enable_legacy_abac` attribute on `google_container_cluster`. This is a negative-value check: if `enable_legacy_abac == true`, the check FAILS. Any other value (`false`, or the attribute omitted — GKE's default is `false`) PASSES.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  enable_legacy_abac = true
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  enable_legacy_abac = false
}
```

## Remediation steps
1. Remove `enable_legacy_abac = true` from the resource, or explicitly set it to `false` (the GKE default is already disabled, so simply omitting the attribute is also compliant).
2. Before disabling, confirm no workloads or tooling depend on ABAC-based access (audit any client using pre-RBAC auth patterns).
3. Migrate any bespoke ABAC policy files to equivalent Kubernetes `Role`/`ClusterRole` and `RoleBinding`/`ClusterRoleBinding` objects.
4. Apply the change; disabling ABAC does not require cluster recreation but will require an in-place cluster update.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEDisableLegacyAuth.py)
- [Google Cloud: Container Cluster - enable_legacy_abac](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_legacy_abac)
