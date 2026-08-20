# CKV2_OCI_5: Ensure Kubernetes Engine Cluster boot volume is configured with in-transit data encryption

## Severity
**LOW** (score: 2.0/10)

Disabling in-transit encryption for OKE node pool block storage leaves data moving between compute instances and block volumes unencrypted, exposing it to interception on the underlying network fabric.

## Summary
This check ensures OCI Container Engine for Kubernetes (OKE) node pools enable `is_pv_encryption_in_transit_enabled` on `node_config_details`, so that data traveling between the compute instance and its attached block/boot volumes is encrypted in transit.

## Applicability
**Checkov framework(s):** `terraform`

Terraform. Applies to the `oci_containerengine_node_pool` resource, specifically the `node_config_details.is_pv_encryption_in_transit_enabled` attribute.

## Why it matters
Even when block/boot volumes are encrypted at rest, the data traveling over the network between a compute instance and OCI's block storage backend (iSCSI traffic) is not automatically encrypted unless in-transit encryption is explicitly enabled. Without it, an attacker positioned on the underlying network path (e.g. through a hypervisor-level compromise, a misconfigured shared network segment, or certain classes of cloud infrastructure attacks) could potentially intercept or tamper with block-level I/O between the node and its volumes — exposing container filesystem contents, secrets baked into images, or ephemeral storage data in flight. For Kubernetes worker nodes specifically, boot/block volumes often contain the container runtime's layer cache, kubelet certificates, and possibly persistent volume data, making in-transit protection an important layer of defense for regulated or sensitive workloads.

## How Checkov evaluates this
Graph-based JSON policy (`OCI_K8EngineClusterBootVolConfigInTransitEncryption.json`). It requires BOTH:
1. `node_config_details.is_pv_encryption_in_transit_enabled` attribute exists on the `oci_containerengine_node_pool` resource.
2. Its value equals (case-insensitive) `"true"`.
It fails if the attribute is missing entirely, or present but set to `false`.

## Non-compliant example
```hcl
resource "oci_containerengine_node_pool" "workers" {
  cluster_id         = oci_containerengine_cluster.oke.id
  compartment_id     = var.compartment_id
  kubernetes_version = "v1.28.2"
  name               = "worker-pool"
  node_shape         = "VM.Standard.E4.Flex"

  node_config_details {
    size = 3
    placement_configs {
      availability_domain = data.oci_identity_availability_domain.ad1.name
      subnet_id            = oci_core_subnet.workers.id
    }
    # is_pv_encryption_in_transit_enabled not set - defaults to disabled
  }

  node_shape_config {
    ocpus         = 2
    memory_in_gbs = 16
  }
}
```

## Remediated example
```hcl
resource "oci_containerengine_node_pool" "workers" {
  cluster_id         = oci_containerengine_cluster.oke.id
  compartment_id     = var.compartment_id
  kubernetes_version = "v1.28.2"
  name               = "worker-pool"
  node_shape         = "VM.Standard.E4.Flex"

  node_config_details {
    size                                   = 3
    is_pv_encryption_in_transit_enabled    = true   # encrypts iSCSI traffic to block/boot volumes
    placement_configs {
      availability_domain = data.oci_identity_availability_domain.ad1.name
      subnet_id            = oci_core_subnet.workers.id
    }
  }

  node_shape_config {
    ocpus         = 2
    memory_in_gbs = 16
  }
}
```

## Remediation steps
1. Add `is_pv_encryption_in_transit_enabled = true` inside the `node_config_details` block of every `oci_containerengine_node_pool` resource.
2. Confirm the chosen node shape supports in-transit encryption (most current-generation VM/BM shapes do; check OCI documentation for shape-specific support).
3. Applying this change to an existing node pool typically requires replacing the node pool's nodes (new nodes are launched with the setting; existing nodes are not modified in place) — plan for a rolling node replacement with appropriate pod disruption budgets.
4. Pair with at-rest encryption (boot volume and block volume encryption, enabled by default on OCI but verify custom KMS keys if used) for full encryption coverage.
5. Validate post-change by checking the node pool's instance configuration in the OCI console or via `oci ce node-pool get`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/oci/OCI_K8EngineClusterBootVolConfigInTransitEncryption.json
