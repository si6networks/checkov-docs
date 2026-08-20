# CKV_ALI_31: Ensure K8s nodepools are set to auto repair
## Severity
**LOW** (score: 2.0/10)

Disabling node pool auto-repair only degrades cluster availability/self-healing after node failure; it does not directly expose data or credentials.

## Summary
This check ensures that Alibaba Cloud Container Service (ACK) Kubernetes node pools have the `auto_repair` management feature enabled, so unhealthy nodes are automatically detected and repaired.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_cs_kubernetes_node_pool`

## Why it matters
Kubernetes worker nodes can enter unhealthy states due to kernel panics, disk pressure, container runtime crashes, or cloud provider host maintenance events. Without automatic node repair, an unhealthy node continues to be scheduled to (or silently drops out of) the cluster, degrading application availability and potentially causing cascading failures as workloads are rescheduled onto remaining healthy nodes under increased load. Auto-repair allows the managed Kubernetes control plane to detect these unhealthy conditions and automatically replace or restart the affected node without requiring manual operator intervention — reducing mean-time-to-recovery and operational toil, particularly for unattended/production clusters.

## How Checkov evaluates this
This is a Python `BaseResourceValueCheck` that inspects the nested attribute path `management/auto_repair` on the `alicloud_cs_kubernetes_node_pool` resource.
- **FAIL** if the `management` block is missing entirely (the check sets `missing_block_result=CheckResult.FAILED`), or if `management.auto_repair` is not set to `true`.
- **PASS** only when `management { auto_repair = true }` is explicitly configured.

## Non-compliant example
```hcl
resource "alicloud_cs_kubernetes_node_pool" "example" {
  name         = "example-nodepool"
  cluster_id   = alicloud_cs_kubernetes.example.id
  vswitch_ids  = [alicloud_vswitch.example.id]
  instance_types = ["ecs.n1.small"]

  # no "management" block at all -> auto_repair is not enabled
}
```

## Remediated example
```hcl
resource "alicloud_cs_kubernetes_node_pool" "example" {
  name         = "example-nodepool"
  cluster_id   = alicloud_cs_kubernetes.example.id
  vswitch_ids  = [alicloud_vswitch.example.id]
  instance_types = ["ecs.n1.small"]

  management {
    auto_repair = true  # <-- added: enables automatic node repair
  }
}
```

## Remediation steps
1. Add a `management` block to the `alicloud_cs_kubernetes_node_pool` resource if one is not present.
2. Set `auto_repair = true` inside that block.
3. Re-apply the Terraform configuration; this is a non-disruptive, in-place update to node pool management settings (no node pool recreation required).
4. Review other `management` sub-options (e.g., `auto_upgrade`, `auto_scaling`) as complementary hardening for unattended cluster operations.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/K8sNodePoolAutoRepair.py)
