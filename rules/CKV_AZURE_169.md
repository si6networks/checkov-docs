# CKV_AZURE_169: Ensure Azure Kubernetes Cluster (AKS) nodes use scale sets

## Severity
**LOW** (score: 2.0/10)

Legacy AvailabilitySet node pools lack autoscaling and zone redundancy, reducing resilience to infrastructure failure; this is an availability-focused gap rather than a direct exploit path.

## Summary
This check ensures that AKS node pools use Virtual Machine Scale Sets (VMSS) as the agent pool type rather than the legacy `AvailabilitySet` type.

## Applicability
- **Terraform**: `azurerm_kubernetes_cluster` (`default_node_pool[0].type`).
- **ARM/Bicep**: `Microsoft.ContainerService/managedClusters` (`properties.agentPoolProfiles[0].type`).

## Why it matters
`AvailabilitySet`-backed node pools are a legacy AKS configuration that does not support the cluster autoscaler, multiple node pools, or availability zones. Running production workloads on an AvailabilitySet pool means the cluster cannot automatically scale nodes in response to load, cannot be spread across zones for resilience against a datacenter/zone failure, and is limited to a single node pool — meaning heterogeneous workloads (e.g., GPU nodes vs. general compute) can't be isolated onto differently sized pools. This makes the cluster both less resilient to infrastructure failures and less elastic under load, and Microsoft has deprecated AvailabilitySet-based clusters in favor of VMSS as the only supported path going forward.

## How Checkov evaluates this
This is a "negative value" check: it inspects the agent pool `type` field and **FAILS** if the value is `"AvailabilitySet"`. Any other value (notably `"VirtualMachineScaleSets"`, which is also the modern default) **PASSES**.
- **Terraform** inspects `default_node_pool/[0]/type` on `azurerm_kubernetes_cluster`.
- **ARM** inspects `properties/agentPoolProfiles/[0]/type` on `Microsoft.ContainerService/managedClusters`.

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  name                = "myAksCluster"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "myaks"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2_v2"
    type       = "AvailabilitySet"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediated example
```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  name                = "myAksCluster"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "myaks"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2_v2"
    type       = "VirtualMachineScaleSets"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Set `type = "VirtualMachineScaleSets"` on the `default_node_pool` block (this is also the provider default if omitted, so simply removing an explicit `"AvailabilitySet"` override resolves this).
2. Changing the agent pool type on an existing cluster is not an in-place update — it requires creating a new cluster/node pool and migrating workloads (plan for downtime or blue/green cutover).
3. Once on VMSS, enable the cluster autoscaler (`auto_scaling_enabled` / min/max node counts) and consider zone redundancy (`zones`) to realize the full benefit of the migration.
4. Verify no external automation or documentation still assumes the AvailabilitySet-specific behavior before cutting over.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSPoolTypeIsScaleSet.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AKSPoolTypeIsScaleSet.py
