# CKV_GCP_68: Ensure Secure Boot for Shielded GKE Nodes is Enabled
## Severity
**LOW** (score: 2.0/10)

Missing Secure Boot removes a post-compromise persistence defense (unsigned bootloader/kernel rootkits) but requires prior node compromise to be exploitable.

## Summary
This check ensures that GKE node pools have Secure Boot enabled as part of their Shielded VM configuration, so nodes only boot verified, unmodified boot components.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `google_container_cluster`, `google_container_node_pool`

## Why it matters
Secure Boot verifies the digital signature of the boot loader, kernel, and kernel modules at boot time, refusing to load any component (including rootkits) that isn't properly signed. Without it, a compromised or tampered boot image — for example one modified by an attacker with access to the VM disk or boot process — could load malicious kernel-level code that persists beneath the visibility of normal host-based monitoring. On a GKE node this is especially dangerous because a compromised node can potentially be used to pivot into other workloads scheduled on it via container escape or kernel exploits. Secure Boot removes this persistence vector by refusing to boot unsigned/altered components at all.

## How Checkov evaluates this
Checkov inspects `node_config[0].shielded_instance_config[0].enable_secure_boot`:
- If `node_config` is present, but `shielded_instance_config` is missing, the check treats this as **FAILED** (the code comment notes the *cluster default* for Secure Boot is actually off, so absence is not safe).
- If `shielded_instance_config` exists and `enable_secure_boot == true`, the check **PASSES**.
- If it exists but is `false` or unset, the check **FAILS**.
- If `node_config` itself is absent (e.g., a `google_container_node_pool` managed elsewhere), the result is `UNKNOWN`.

## Non-compliant example
```hcl
resource "google_container_node_pool" "nodes" {
  name       = "default-pool"
  cluster    = google_container_cluster.primary.name
  node_count = 3

  node_config {
    machine_type = "e2-medium"
    # shielded_instance_config omitted -> Secure Boot not enabled
  }
}
```

## Remediated example
```hcl
resource "google_container_node_pool" "nodes" {
  name       = "default-pool"
  cluster    = google_container_cluster.primary.name
  node_count = 3

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
1. Add a `shielded_instance_config` block inside `node_config` on every `google_container_cluster` and `google_container_node_pool` resource.
2. Set `enable_secure_boot = true`.
3. While editing, also set `enable_integrity_monitoring = true` (see CKV_GCP_72) since both live in the same block.
4. Shielded VM features require Container-Optimized OS or Ubuntu node images; verify your `image_type` supports Secure Boot before enabling.
5. Enabling Secure Boot on an existing node pool requires recreating the node pool (nodes must be re-provisioned); plan for a rolling node pool replacement to avoid workload disruption.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKESecureBootforShieldedNodes.py)
- [Google Cloud: Shielded GKE Nodes](https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes)
