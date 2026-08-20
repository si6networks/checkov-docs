# CKV_GCP_72: Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled
## Severity
**LOW** (score: 2.0/10)

Missing Integrity Monitoring is a detection gap (loss of visibility into boot-chain tampering) rather than a control that itself prevents an attack.

## Summary
This check ensures GKE node pools have Integrity Monitoring enabled as part of their Shielded VM configuration, so unexpected changes to the boot sequence are detected and reported.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `google_container_cluster`, `google_container_node_pool`

## Why it matters
Integrity Monitoring continuously compares the node's boot measurements (via the vTPM) against a known-good baseline and surfaces any divergence as findings in Cloud Monitoring/Security Command Center. Without it, even if Secure Boot is enabled to block obviously unsigned components, there is no ongoing detection mechanism for subtler tampering of the boot chain — an operator has no automated signal that a node's boot integrity has changed over time (e.g., due to a compromised custom image, a supply-chain issue in the node's base image, or firmware-level tampering). This blinds incident responders to a whole class of low-level persistence techniques, delaying detection of a compromised node until its effects surface elsewhere (e.g., anomalous outbound traffic or workload behavior).

## How Checkov evaluates this
Checkov inspects `node_config[0].shielded_instance_config[0].enable_integrity_monitoring`:
- If `node_config` is present but has no `shielded_instance_config` block, the check treats this as a **PASS** (the code comments that Integrity Monitoring's default is `true`, so its absence is safe).
- If `shielded_instance_config` exists and `enable_integrity_monitoring == true`, PASS.
- If it exists and is explicitly `false` (or any other value), FAIL.
- If `node_config` itself is absent, the result is `UNKNOWN` (e.g., configuration may live on a separately-managed node pool).

## Non-compliant example
```hcl
resource "google_container_node_pool" "nodes" {
  name    = "default-pool"
  cluster = google_container_cluster.primary.name

  node_config {
    machine_type = "e2-medium"

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = false
    }
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

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
}
```

## Remediation steps
1. Add or update the `shielded_instance_config` block inside `node_config` to set `enable_integrity_monitoring = true`.
2. Combine with Secure Boot (CKV_GCP_68) and cluster-level `enable_shielded_nodes` (CKV_GCP_71) for full Shielded Node protection.
3. Route the resulting boot-integrity findings to Security Command Center or a monitoring alert so divergences are actually acted upon, not just recorded.
4. Enabling this on an existing node pool requires node recreation; plan a rolling upgrade.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEEnsureIntegrityMonitoring.py)
- [Google Cloud: Shielded GKE Nodes](https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes)
