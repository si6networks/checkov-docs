# CKV_AZURE_242: Ensure isolated compute is enabled for Synapse Spark pools

## Severity
**LOW** (score: 2.0/10)

Without isolated compute, Synapse Spark pool workloads can share underlying compute with other tenants' jobs, creating a moderate risk of cross-workload data leakage or noisy-neighbor interference.

## Summary
This check ensures Azure Synapse Spark pools have compute isolation enabled, dedicating physical hardware to the pool instead of sharing hardware with other tenants.

## Applicability
- **Terraform**: `azurerm_synapse_spark_pool` resources — inspects the `compute_isolation_enabled` attribute.
- **ARM/Bicep**: `Microsoft.Synapse/workspaces/bigDataPools` — inspects `properties.isComputeIsolationEnabled`.

## Why it matters
By default, Synapse Spark pool compute nodes run on shared multi-tenant hardware alongside other Azure customers' workloads (with standard hypervisor-level isolation between VMs). For workloads with strict regulatory or contractual requirements — e.g., government, financial services, or healthcare data processing that mandates dedicated/isolated hardware, not merely logical isolation — this shared-hardware model may not satisfy compliance obligations, and it theoretically increases exposure to hypervisor-level side-channel or noisy-neighbor risks (however small in practice) compared to workloads with guaranteed physical isolation. Enabling compute isolation ensures the Spark pool's VMs run on hardware dedicated to that isolated pool, which is often specifically required to meet FedRAMP, PCI-DSS, or similar compliance mandates for processing highly sensitive data.

## How Checkov evaluates this
Both are `BaseResourceValueCheck`s:
- **Terraform**: inspects `compute_isolation_enabled` on `azurerm_synapse_spark_pool`. PASSES only if explicitly `true`; FAILS if omitted or `false`.
- **ARM**: inspects `properties.isComputeIsolationEnabled` on `Microsoft.Synapse/workspaces/bigDataPools`. Same pass/fail logic.

## Non-compliant example
```hcl
resource "azurerm_synapse_spark_pool" "example" {
  name                 = "examplesparkpool"
  synapse_workspace_id = azurerm_synapse_workspace.example.id
  node_size_family     = "MemoryOptimized"
  node_size            = "Small"
  node_count           = 3
  # compute_isolation_enabled not set -> defaults to false, FAILS
}
```

## Remediated example
```hcl
resource "azurerm_synapse_spark_pool" "example" {
  name                       = "examplesparkpool"
  synapse_workspace_id       = azurerm_synapse_workspace.example.id
  node_size_family           = "MemoryOptimized"
  node_size                  = "Small"
  node_count                 = 3
  compute_isolation_enabled  = true   # <-- dedicated hardware, PASSES
}
```

## Remediation steps
1. Set `compute_isolation_enabled = true` on the `azurerm_synapse_spark_pool` resource (or `properties.isComputeIsolationEnabled: true` in ARM/Bicep).
2. Confirm the target region and node size/family support compute isolation — Azure limits isolated hardware SKUs to specific VM families and regions, so you may need to adjust `node_size_family`/`node_size`.
3. Expect a meaningfully higher cost for dedicated/isolated hardware compared to shared multi-tenant compute; apply this only to workloads with an actual compliance or contractual requirement, not blanket enablement.
4. This is typically a creation-time setting; changing it on an existing pool may require recreating the Spark pool.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureSparkPoolIsolatedComputeEnabled.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureSparkPoolIsolatedComputeEnabled.py
- Azure docs: https://learn.microsoft.com/en-us/azure/synapse-analytics/spark/apache-spark-pool-configurations
