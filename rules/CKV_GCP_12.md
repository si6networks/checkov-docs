# CKV_GCP_12: Ensure Network Policy is enabled on Kubernetes Engine Clusters

## Severity
**LOW** (score: 2.0/10)

Without a GKE network policy, pods can freely communicate with each other regardless of namespace or label, so a single compromised pod can reach and attack any other workload in the cluster.

## Summary
This check requires GKE clusters (`google_container_cluster`) to have Kubernetes Network Policy enabled (or to use the Dataplane V2 "ADVANCED_DATAPATH" provider, which enforces network policy natively), so that pod-to-pod traffic can be restricted rather than left fully open by default.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`
- **Check type:** resource

## Why it matters
By default, Kubernetes allows unrestricted network traffic between all pods in a cluster, regardless of namespace. This means that if any single pod is compromised (via a vulnerable dependency, a container escape, a malicious image, or a supply-chain attack), the attacker can freely move laterally to reach any other workload in the cluster — including sensitive internal services, databases, metadata endpoints, or admin tooling — with no network-layer barrier in the way. Network Policy support (backed by Calico or GKE's Dataplane V2/Cilium) lets you define namespace- and label-based ingress/egress rules, enforcing least-privilege networking between workloads and substantially limiting the blast radius of a single compromised pod.

## How Checkov evaluates this
The check (`GKENetworkPolicyEnabled`) inspects the `network_policy` block on `google_container_cluster`:
- If `network_policy` is present and its `enabled` attribute is `true`, the check **PASSES**.
- If `network_policy.enabled` is `false`, it still **PASSES** if `datapath_provider` is set to `"ADVANCED_DATAPATH"` (GKE Dataplane V2), since Dataplane V2 enforces network policy at the datapath layer independent of the legacy `network_policy` add-on.
- In every other case — `network_policy` block missing, `enabled` missing, or `enabled = false` without Dataplane V2 — the check **FAILS**.
- Evaluated key: `network_policy/[0]/enabled`.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "primary-cluster"
  location = "us-central1"

  initial_node_count = 3
  # no network_policy block at all - all pod-to-pod traffic is unrestricted
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "primary-cluster"
  location = "us-central1"

  initial_node_count = 3

  network_policy {
    enabled  = true
    provider = "CALICO"
  }
}
```

## Remediation steps
1. Add a `network_policy` block to the `google_container_cluster` resource with `enabled = true` (and optionally `provider = "CALICO"`).
2. Alternatively, if using GKE Dataplane V2, set `datapath_provider = "ADVANCED_DATAPATH"` on the cluster, which enforces network policy natively without the separate `network_policy` add-on (this is the default and recommended path for new clusters, including Autopilot).
3. Enabling network policy on an existing cluster is a mutable update but can briefly disrupt node pool operations — plan for a maintenance window on production clusters.
4. After enabling, define actual `NetworkPolicy` Kubernetes objects (default-deny plus explicit allow rules) — enabling the feature alone does not restrict anything until policies are applied.
5. For GKE Autopilot clusters, Dataplane V2 is enabled by default, which should already satisfy this check; verify with `terraform plan` that no explicit override disables it.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKENetworkPolicyEnabled.py)
- [GKE Network Policy documentation](https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy)
- [GKE Dataplane V2 documentation](https://cloud.google.com/kubernetes-engine/docs/concepts/dataplane-v2)
