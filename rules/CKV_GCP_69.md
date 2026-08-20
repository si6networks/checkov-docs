# CKV_GCP_69: Ensure the GKE Metadata Server is Enabled
## Severity
**LOW** (score: 2.0/10)

Without the GKE Metadata Server, any Pod can query the raw node metadata server and steal the node's often broadly-privileged service account token, a well-known container-to-cloud privilege-escalation path.

## Summary
This check ensures GKE node pools use the GKE Metadata Server (Workload Identity's metadata proxy) instead of exposing the raw GCE instance metadata server directly to Pods.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `google_container_cluster`, `google_container_node_pool`

## Why it matters
By default, any Pod on a GKE node can reach the underlying VM's GCE metadata server at `169.254.169.254`, including the node's service account credentials. This is a well-known privilege-escalation path: a compromised or malicious Pod (e.g. via a vulnerable application or a supply-chain-compromised image) can query the metadata server, steal the node's service account access token, and use it to call Google Cloud APIs with the node's (often broad) IAM permissions — far beyond what the Pod's own workload should have. The GKE Metadata Server (`workload_metadata_config`) filters and proxies metadata requests, blocking access to the node's credentials and enabling Workload Identity so Pods instead assume scoped, per-Kubernetes-service-account IAM identities. Without it, container escape or SSRF-style bugs in an application become full node-credential theft.

## How Checkov evaluates this
Checkov inspects `node_config[0].workload_metadata_config` for either:
- `mode == "GKE_METADATA"` (current provider syntax), or
- `node_metadata == "GKE_METADATA_SERVER"` (deprecated older provider syntax)

Either match causes a PASS. If `node_config` is missing, `workload_metadata_config` is missing, or the mode is something else (e.g. `GCE_METADATA` / `EXPOSE` / `SECURE`), the check FAILS.

## Non-compliant example
```hcl
resource "google_container_node_pool" "nodes" {
  name    = "default-pool"
  cluster = google_container_cluster.primary.name

  node_config {
    machine_type = "e2-medium"
    # workload_metadata_config omitted -> raw GCE metadata reachable from Pods
  }
}
```

## Remediated example
```hcl
resource "google_container_node_pool" "nodes" {
  name    = "default-pool"
  cluster = google_container_cluster.primary.name

  node_config {
    machine_type = "e2-medium"

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}
```

## Remediation steps
1. Enable Workload Identity at the cluster level (`workload_identity_config { workload_pool = "<project>.svc.id.goog" }`) if not already enabled.
2. Add `workload_metadata_config { mode = "GKE_METADATA" }` inside `node_config` for every node pool.
3. Bind Kubernetes ServiceAccounts to IAM ServiceAccounts via `iam.workloadIdentityUser` role bindings and annotate the KSA with `iam.gke.io/gcp-service-account`.
4. Update workloads to use the bound Kubernetes ServiceAccount instead of relying on node-level credentials.
5. Changing `workload_metadata_config` on an existing node pool requires recreating the nodes; roll this out pool-by-pool to avoid downtime.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEMetadataServerIsEnabled.py)
- [Google Cloud: Protecting cluster metadata](https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata)
