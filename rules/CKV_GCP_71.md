# CKV_GCP_71: Ensure Shielded GKE Nodes are Enabled
## Severity
**LOW** (score: 2.0/10)

Disabling cluster-wide Shielded Nodes removes the prerequisite for verified boot and integrity attestation, enabling undetected rootkit/persistence techniques if a node is later compromised.

## Summary
This check ensures the cluster-wide Shielded GKE Nodes feature is enabled, which is the prerequisite for verified boot integrity and rootkit protections on node VMs.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`

## Why it matters
Shielded Nodes provide the underlying vTPM-backed verified boot, integrity measurement, and Secure Boot capability for GKE node VMs. Without this feature enabled at the cluster level, nodes run on standard (non-shielded) Compute Engine VMs, and neither Secure Boot nor Integrity Monitoring can function — regardless of what is configured in individual `node_config` blocks. This leaves the cluster vulnerable to boot- and kernel-level persistence attacks: an attacker who compromises a node (via a container escape, host vulnerability, or malicious disk image) can install a rootkit or modify boot components that survives reboots and evades typical host-based intrusion detection, since there is no cryptographic attestation of the boot chain to compare against.

## How Checkov evaluates this
Checkov reads the top-level `enable_shielded_nodes` attribute on `google_container_cluster`. This is a negative-value check: if `enable_shielded_nodes == false`, the check FAILS. Any other value — `true`, or the attribute omitted (GKE's default is `true` for new clusters using recent API versions) — PASSES.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  enable_shielded_nodes = false
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  enable_shielded_nodes = true
}
```

## Remediation steps
1. Remove `enable_shielded_nodes = false`, or explicitly set `enable_shielded_nodes = true` on the cluster resource.
2. Also enable `shielded_instance_config` (Secure Boot and Integrity Monitoring) on each node pool's `node_config` — see CKV_GCP_68 and CKV_GCP_72 — since the cluster-level flag alone does not turn on those individual protections.
3. Confirm node images are Shielded-VM compatible (Container-Optimized OS or Ubuntu); some custom or legacy images may not support this.
4. Enabling Shielded Nodes on an existing cluster requires the node pools to be recreated; plan a rolling replacement.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEEnableShieldedNodes.py)
- [Google Cloud: Shielded GKE Nodes](https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes)
