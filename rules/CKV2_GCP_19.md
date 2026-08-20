# CKV2_GCP_19: Ensure GCP Kubernetes engine clusters have 'alpha cluster' feature disabled
## Severity
**LOW** (score: 2.0/10)

Enabling GKE alpha cluster features disables node auto-upgrade/auto-repair and runs unsupported, unpatched Kubernetes code paths, weakening the cluster's ongoing security maintenance rather than exposing it directly.

## Summary
This check ensures that GKE clusters do not have the Kubernetes alpha features flag (`enable_kubernetes_alpha`) turned on.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`

## Why it matters
GKE "alpha clusters" enable all Kubernetes alpha APIs and features on the cluster. Alpha features are unstable, unsupported, not covered by GKE's SLA, and are never enabled for production upgrades — an alpha cluster is automatically deleted after 30 days. More importantly for security posture, alpha APIs receive no deprecation/security-patch guarantees and can expose experimental, insufficiently-hardened functionality (including APIs with weaker or absent RBAC/admission-control enforcement) to the entire cluster. Enabling this flag on any cluster that handles real workloads or sensitive data creates unpredictable behavior, blocks live upgrades, and increases the attack surface through code paths that have not gone through the same security review as GA features.

## How Checkov evaluates this
This is a Terraform graph-based check (JSON policy) that inspects the `google_container_cluster` resource's `enable_kubernetes_alpha` attribute:
- **FAIL** if `enable_kubernetes_alpha` is set to `true`.
- **PASS** if the attribute is absent (defaults to `false`) or explicitly set to `false` (comparison is case-insensitive).

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name                     = "my-gke-cluster"
  location                 = "us-central1"
  initial_node_count       = 1
  enable_kubernetes_alpha  = true
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name                     = "my-gke-cluster"
  location                 = "us-central1"
  initial_node_count       = 1
  enable_kubernetes_alpha  = false  # or simply omit the attribute
}
```

## Remediation steps
1. Locate any `google_container_cluster` resources with `enable_kubernetes_alpha = true`.
2. Remove the attribute or set it to `false`.
3. Note: `enable_kubernetes_alpha` forces resource replacement in Terraform (it cannot be toggled in place) — changing it will destroy and recreate the cluster, causing downtime. Plan a maintenance window.
4. If alpha features are genuinely needed for experimentation, use a short-lived, isolated, non-production project/cluster instead of enabling the flag on a shared cluster.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPdisableAlphaClusterFeatureInKubernetesEngineClusters.json
- GCP docs: https://cloud.google.com/kubernetes-engine/docs/concepts/alpha-clusters
