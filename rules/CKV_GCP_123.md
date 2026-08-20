# CKV_GCP_123: GKE Don't Use NodePools in the Cluster configuration

## Severity
**LOW** (score: 2.0/10)

Defining node pools inline in the cluster resource is an operational/maintainability best practice (forcing full cluster recreation for node pool changes) rather than a direct security exposure.

## Summary
This check fails when a `google_container_cluster` resource defines an inline `node_pool` block instead of managing node pools as separate `google_container_node_pool` resources, unless the default node pool is being explicitly removed (`remove_default_node_pool = true`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`
- **Check type:** resource (negative value check)

## Why it matters
This is primarily a reliability/operational-safety check rather than a pure confidentiality/integrity issue, but operational safety has direct security implications (unplanned cluster recreation can cause outages, disrupt security controls mid-rotation, and force workloads to be rescheduled in an uncontrolled way). Per the Google Terraform provider's own documentation, node pools defined inline inside `google_container_cluster.node_pool` cannot be added, removed, or resized without triggering a full recreation of the cluster resource. Since GKE clusters are foundational infrastructure (hosting potentially many services, secrets mounted via CSI, network policies, RBAC configuration, etc.), forcing a cluster recreation to scale or update a node pool is highly disruptive in production: it can cause extended downtime, force re-issuance of any cluster-bound credentials/certificates, and increases the chance of configuration drift or human error during a high-stakes, all-or-nothing operation.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck`:
- **Inspected key:** `node_pool`
- **Forbidden values:** `[ANY_VALUE]` — i.e., if `node_pool` is set to anything at all, that's normally a violation.
- **Exception:** the check has an `excluded_key` of `remove_default_node_pool`. If that attribute is present and evaluates to `True` (`check_excluded_condition`), the failure condition is suppressed — this covers the common pattern of using an inline `node_pool` block only to immediately remove the GKE-created default pool, with real workloads running on separately-managed `google_container_node_pool` resources.
- **FAIL:** `node_pool` block(s) present, and `remove_default_node_pool` is not `true`.
- **PASS:** no `node_pool` block present, or `node_pool` present alongside `remove_default_node_pool = true`.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "primary-cluster"
  location = "us-central1"

  node_pool {
    name       = "default-pool"
    node_count = 3

    node_config {
      machine_type = "e2-medium"
    }
  }
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "primary-cluster"
  location = "us-central1"

  remove_default_node_pool = true   # <-- removes the GKE-provisioned default pool
  initial_node_count       = 1
}

resource "google_container_node_pool" "primary_nodes" {
  name       = "primary-node-pool"
  cluster    = google_container_cluster.primary.name
  location   = google_container_cluster.primary.location
  node_count = 3

  node_config {
    machine_type = "e2-medium"
  }
}
```

## Remediation steps
1. Remove any inline `node_pool` block from `google_container_cluster` resources.
2. Add `remove_default_node_pool = true` and `initial_node_count = 1` (required minimum) to the cluster resource so GKE's auto-created default pool is torn down immediately after cluster creation.
3. Define each real node pool as a separate `google_container_node_pool` resource referencing the cluster.
4. **Caution:** applying this change to an existing cluster that currently has an inline `node_pool` will likely force cluster recreation (since it changes how the default pool is managed) — plan this as a deliberate, scheduled migration, ideally by standing up a new cluster and migrating workloads rather than modifying in place.
5. For GKE Autopilot clusters, node pools are managed automatically by GKE and this concern does not apply in the same way — check whether the `enable_autopilot` field is set before treating this as required.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEDontUseNodePools.py)
- [Terraform `google_container_cluster` resource — node_pool notes](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#node_pool)
