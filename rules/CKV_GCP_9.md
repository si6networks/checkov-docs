# CKV_GCP_9: Ensure 'Automatic node repair' is enabled for Kubernetes Clusters
## Severity
**LOW** (score: 2.0/10)

Automatic node repair is an availability/operational-resilience feature for unhealthy GKE nodes and has no direct bearing on confidentiality or a concrete attack path.

## Summary
This check requires `google_container_node_pool` resources to enable node auto-repair (`management.auto_repair = true`), so GKE automatically repairs unhealthy nodes without manual intervention.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_container_node_pool`
- **Check type:** resource (attribute-value check on the nested `management` block)

## Why it matters
GKE periodically runs health checks against each node; a node that repeatedly fails these checks (kubelet unresponsive, disk corruption, kernel deadlock, etc.) becomes unreliable both for scheduling new workloads and, more importantly, for continuing to run existing pods correctly. Without auto-repair, a failing node stays in the cluster until an operator notices and manually cordons/drains/replaces it — during that window workloads scheduled on it may crash-loop, silently degrade (serving errors or stale data), or in this repo's context (`fleetware`, suggesting robot fleet infrastructure), potentially propagate faulty control/telemetry data from an unhealthy node. Reliability and availability, not just cost, are at stake: auto-repair converts a class of infrastructure failures from "requires paging a human" into "self-healing," which matters significantly for any workload with real-time or safety-adjacent characteristics.

## How Checkov evaluates this
The check (`GKENodePoolAutoRepairEnabled`, a `BaseResourceValueCheck`) inspects the attribute path `management/[0]/auto_repair` on `google_container_node_pool`.
- **PASS**: the `management` block sets `auto_repair = true`.
- **FAIL**: the `management` block is absent, or `auto_repair` is missing/`false`.

## Non-compliant example
```hcl
resource "google_container_node_pool" "nodes" {
  name       = "fleet-node-pool"
  cluster    = google_container_cluster.fleet.name
  location   = "us-central1"
  node_count = 3

  node_config {
    machine_type = "e2-standard-4"
  }
  # No management block -> auto-repair not enabled
}
```

## Remediated example
```hcl
resource "google_container_node_pool" "nodes" {
  name       = "fleet-node-pool"
  cluster    = google_container_cluster.fleet.name
  location   = "us-central1"
  node_count = 3

  node_config {
    machine_type = "e2-standard-4"
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}
```

## Remediation steps
1. Add a `management` block to the `google_container_node_pool` resource with `auto_repair = true`.
2. Consider also enabling `auto_upgrade = true` for consistency, but evaluate separately whether auto-upgrade fits your change-control process (auto-repair and auto-upgrade are independent settings).
3. This is generally a safe, non-disruptive, in-place update (GKE applies the management policy without recreating existing nodes).
4. For workloads sensitive to sudden node replacement (e.g., long-running batch jobs), pair auto-repair with appropriate `PodDisruptionBudget`s so repairs don't cause avoidable service impact.
5. Verify the node pool's `google_container_cluster` release channel/version supports auto-repair (it is broadly available, but confirm for any legacy static-version clusters).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKENodePoolAutoRepairEnabled.py
- GCP docs: https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-repair
