# CKV_GCP_10: Ensure 'Automatic node upgrade' is enabled for Kubernetes Clusters

## Severity
**LOW** (score: 2.0/10)

Without automatic node upgrades, GKE node pools can silently drift onto outdated, unpatched Kubernetes/OS versions, leaving known vulnerabilities unremediated over time.

## Summary
This check ensures that a GKE node pool (`google_container_node_pool`) has automatic node upgrades enabled via its `management` block, so nodes are kept current with GKE-supported Kubernetes versions and patches automatically.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework**: Terraform
- **Resource type**: `google_container_node_pool`

## Why it matters
GKE node pools run the node OS, kubelet, and container runtime that host every workload scheduled to them. Without automatic node upgrades enabled:

- **Unpatched kernel and kubelet vulnerabilities linger**: Node-level CVEs (container escape bugs, kubelet API vulnerabilities, container runtime flaws) are only fixed if someone manually triggers an upgrade; in practice, manual upgrade discipline is inconsistent across teams and node pools are frequently forgotten.
- **Version skew with control plane**: GKE regularly deprecates and auto-upgrades the control plane; if node pools fall too far behind the control plane's Kubernetes version, GKE's supported skew policy can be violated, leading to workload scheduling issues or forced, larger, higher-risk upgrades later.
- **Delayed adoption of security fixes**: Kubernetes itself ships regular security patch releases; without auto-upgrade, a cluster can silently run known-vulnerable versions for months, widening the exposure window to publicly disclosed CVEs.
- **Operational surprise at upgrade time**: Deferred manual upgrades tend to accumulate multiple minor versions of drift, making the eventual upgrade riskier and more likely to break workloads, compared to small, frequent, automatic increments.

## How Checkov evaluates this
The check (`GKENodePoolAutoUpgradeEnabled`) is a positive-value check that looks for the nested attribute path `management/[0]/auto_upgrade/[0]` on the `google_container_node_pool` resource:
- **PASSES** if `management { auto_upgrade = true }` is set.
- **FAILS** if `auto_upgrade` is absent or set to `false` within the `management` block.

## Non-compliant example
```hcl
resource "google_container_node_pool" "nodes" {
  name       = "default-pool"
  cluster    = google_container_cluster.primary.name
  location   = "us-central1"
  node_count = 3

  management {
    auto_upgrade = false
    auto_repair  = true
  }
}
```

## Remediated example
```hcl
resource "google_container_node_pool" "nodes" {
  name       = "default-pool"
  cluster    = google_container_cluster.primary.name
  location   = "us-central1"
  node_count = 3

  management {
    auto_upgrade = true
    auto_repair  = true
  }
}
```

## Remediation steps
1. Add or update the `management` block on every `google_container_node_pool` resource to set `auto_upgrade = true`.
2. Also enable `auto_repair = true` alongside it (not enforced by this specific check, but a standard companion setting for unattended node health).
3. If the cluster uses a release channel (`release_channel` on `google_container_cluster`), node auto-upgrade is generally required/expected and aligns with the channel's managed upgrade cadence.
4. Applying this change to an existing node pool does not require pool recreation, but GKE will perform a rolling upgrade of nodes according to your configured maintenance window/upgrade settings — schedule appropriately to avoid workload disruption during upgrade windows.
5. Pair with a `maintenance_policy` on the cluster to control *when* automatic upgrades occur, minimizing surprise during business-critical hours.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKENodePoolAutoUpgradeEnabled.py
- GCP GKE node auto-upgrade documentation: https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-upgrades
