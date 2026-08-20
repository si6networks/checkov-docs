# CKV_AZURE_150: Ensure Machine Learning Compute Cluster Minimum Nodes Set To 0

## Severity
**LOW** (score: 2.0/10)

Setting a minimum node count above zero for an ML compute cluster is primarily a cost-and-idle-resource control, not a direct confidentiality, integrity, or availability exposure.

## Summary
This check ensures that an Azure Machine Learning compute cluster's `scale_settings.min_node_count` is set to `0`, so that the cluster scales down to zero nodes (rather than always keeping compute nodes idle and running) when not in use.

## Applicability
- **Framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_machine_learning_compute_cluster`

## Why it matters
This is primarily a cost-control and attack-surface-reduction check rather than a classic confidentiality/integrity check, though Checkov categorizes it under general security. A compute cluster with a non-zero minimum node count keeps VM instances provisioned and running at all times, even when no training/inference jobs are active. That means:
- Idle compute nodes remain a persistent, always-on attack surface (patchable OS, running agents, network listeners) instead of being torn down between jobs.
- Idle nodes accrue unnecessary cost, and unexpected cost spikes are themselves an operational/security signal (e.g. cryptomining abuse of compute resources is easier to hide when "always-on" nodes are the norm).
Setting `min_node_count = 0` ensures nodes are provisioned on-demand and de-provisioned when idle, minimizing the standing footprint of compute resources.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects `scale_settings[0].min_node_count`:
- **PASS** only if `min_node_count` is explicitly `0`.
- **FAIL** if it is any other value (including if omitted, since there's no `missing_block_result` override — default missing-block behavior is `FAILED` for `BaseResourceValueCheck`).

## Non-compliant example
```hcl
resource "azurerm_machine_learning_compute_cluster" "example" {
  name                          = "example-cluster"
  location                      = azurerm_resource_group.example.location
  vm_priority                   = "Dedicated"
  vm_size                       = "STANDARD_DS2_V2"
  machine_learning_workspace_id = azurerm_machine_learning_workspace.example.id

  scale_settings {
    min_node_count                       = 1   # nodes never fully scale down
    max_node_count                       = 4
    scale_down_nodes_after_idle_duration = "PT30S"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediated example
```hcl
resource "azurerm_machine_learning_compute_cluster" "example" {
  name                          = "example-cluster"
  location                      = azurerm_resource_group.example.location
  vm_priority                   = "Dedicated"
  vm_size                       = "STANDARD_DS2_V2"
  machine_learning_workspace_id = azurerm_machine_learning_workspace.example.id

  scale_settings {
    min_node_count                       = 0   # scales to zero when idle
    max_node_count                       = 4
    scale_down_nodes_after_idle_duration = "PT30S"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Set `scale_settings.min_node_count = 0` on every `azurerm_machine_learning_compute_cluster` resource.
2. Tune `scale_down_nodes_after_idle_duration` to balance cold-start latency against idle cost/exposure — a short idle duration scales down faster but may add latency for the next job.
3. If jobs require guaranteed warm capacity for latency reasons, document and explicitly accept the exception rather than leaving `min_node_count` non-zero by default.
4. This is a configuration-only change; verify with `terraform plan` whether your provider version applies it in-place or requires recreation.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MLComputeClusterMinNodes.py)
- [Azure Machine Learning compute cluster documentation](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-create-attach-compute-cluster)
