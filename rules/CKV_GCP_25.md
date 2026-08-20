# CKV_GCP_25: Ensure Kubernetes Cluster is created with Private cluster enabled
## Severity
**MEDIUM** (score: 5.0/10)

Without a private cluster configuration, GKE nodes can be assigned public IPs, directly exposing worker nodes to the internet and materially increasing the risk of unauthorized network access to cluster workloads.

## Summary
This check fails when a `google_container_cluster` does not configure a `private_cluster_config` block, meaning cluster nodes (and potentially the control plane) have public IP addresses.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`
- **Check type:** resource

## Why it matters
In a non-private GKE cluster, worker nodes are assigned public IP addresses by default, making them directly reachable from the internet unless firewall rules happen to block everything. Every publicly-addressable node is an additional exposed surface for port scanning, kubelet API probing, and exploitation of any node-level service inadvertently exposed via NodePort or hostNetwork. A **private cluster** removes public IPs from nodes (they only have internal RFC 1918 addresses, reaching the internet only via Cloud NAT if configured) and can also restrict the control-plane endpoint to a private IP. This significantly shrinks the attack surface, is a baseline expectation for regulated workloads, and aligns with the general "internal-by-default, public-by-exception" network security posture.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using `ANY_VALUE` matching on `private_cluster_config`:
- **PASS** — the `private_cluster_config` block is present (any configuration, including one that only sets `enable_private_nodes = false` — the check only verifies the block's presence, not its inner values).
- **FAIL** — the block is absent entirely.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "public-cluster"
  location = "us-central1"
  # no private_cluster_config -> nodes get public IPs -> FAILS
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "private-cluster"
  location = "us-central1"

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false   # set true to also make the control plane private
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }
}
```

## Remediation steps
1. Add a `private_cluster_config` block with at minimum `enable_private_nodes = true`.
2. Set `master_ipv4_cidr_block` to a dedicated `/28` CIDR for the control plane's peered VPC.
3. For maximum lockdown, also set `enable_private_endpoint = true` (control plane has no public IP at all) — but ensure you have Cloud VPN/Interconnect/bastion connectivity to reach it, since `kubectl` from an unpeered network will otherwise be unable to reach the API server.
4. Combine with `master_authorized_networks_config` (CKV_GCP_20) even for private clusters, since the private endpoint can still be reached from anywhere within the authorized VPC/peered networks unless further scoped.
5. **This requires cluster replacement** — private-cluster networking mode cannot be toggled on an existing cluster in place. Plan a migration window.
6. Ensure NAT (Cloud NAT) is configured if private nodes need outbound internet access (e.g., pulling public container images).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEPrivateClusterConfig.py
- GCP docs: https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters
