# CKV_GCP_64: Ensure clusters are created with Private Nodes

## Severity
**LOW** (score: 2.0/10)

Nodes without the private-nodes configuration can receive public IP addresses, directly expanding a GKE cluster's node-level network attack surface to the internet.

## Summary
This check fails when a `google_container_cluster` (GKE cluster) does not have a `private_cluster_config` block configured, meaning cluster nodes are provisioned with externally-routable IP addresses rather than being restricted to private (internal) IPs.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_container_cluster`
- **Check type:** resource value check (Kubernetes category) — expects any value (`ANY_VALUE`) to be set for `private_cluster_config`

## Why it matters
GKE nodes provisioned without "private nodes" get external IP addresses on their VMs, making the underlying Compute Engine instances directly reachable from the public internet (subject to firewall rules). This substantially widens the attack surface: node VMs can be targeted directly by internet-wide scanning and exploitation attempts against the node's OS, kubelet API, or other exposed services, independent of any Kubernetes-level network policy. Private nodes remove external IPs from the node VMs entirely, so they can only be reached via internal GCP networking (VPC, Cloud NAT for egress), forcing all inbound access to route through explicitly-controlled paths (bastion, VPN, Interconnect) rather than being exposed by default. This is one of the most impactful "reduce attack surface" controls available for GKE and is a standard requirement in hardened Kubernetes deployment baselines (CIS GKE Benchmark).

## How Checkov evaluates this
The check (`GKEPrivateNodes`) is a `BaseResourceValueCheck` that inspects the `private_cluster_config` attribute and accepts `ANY_VALUE` as passing:
- **PASS** if `private_cluster_config` block is present with any configuration at all.
- **FAIL** if `private_cluster_config` is absent entirely.

Note: because it only checks for the *presence* of the block (not its contents), a `private_cluster_config` block with `enable_private_nodes = false` would still technically satisfy this specific check's presence test — always explicitly verify `enable_private_nodes = true` within the block even though Checkov's `ANY_VALUE` matcher here doesn't itself enforce that sub-field.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "app-cluster"
  location = "us-central1"

  initial_node_count = 1
  # no private_cluster_config — nodes get external IPs
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "app-cluster"
  location = "us-central1"

  initial_node_count = 1

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }
}
```

## Remediation steps
1. Add a `private_cluster_config` block to the `google_container_cluster` resource with `enable_private_nodes = true`.
2. Choose whether the control-plane endpoint should also be private (`enable_private_endpoint = true`) — if kept public, restrict access via `master_authorized_networks_config`.
3. Set up Cloud NAT (or an equivalent egress path) so private nodes can still reach the internet for image pulls and package installs, since they no longer have external IPs.
4. Be aware: `enable_private_nodes` typically cannot be toggled on an existing cluster without recreating the node pools (and in many cases the cluster) — plan this as a migration, not an in-place edit.
5. Re-scan with Checkov to confirm compliance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEPrivateNodes.py)
- [GKE: Private cluster concepts](https://cloud.google.com/kubernetes-engine/docs/concepts/private-cluster-concept)
