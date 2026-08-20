# CKV_AZURE_171: Ensure AKS cluster upgrade channel is chosen

## Severity
**LOW** (score: 2.0/10)

Disabling the automatic upgrade channel means the cluster's control plane and kubelet routinely miss vendor security patches, allowing known, exploitable Kubernetes CVEs to accumulate unaddressed over time.

## Summary
This check ensures that an AKS cluster has an automatic upgrade channel configured (anything other than `"none"`), so the cluster receives Kubernetes version and/or node image upgrades on a defined cadence.

## Applicability
- **Terraform**: `azurerm_kubernetes_cluster` (`automatic_channel_upgrade` or the legacy `automatic_upgrade_channel` attribute).
- **ARM/Bicep**: `Microsoft.ContainerService/managedClusters` (`properties.autoUpgradeProfile.upgradeChannel`).

## Why it matters
Kubernetes releases are supported for a limited window, and unpatched clusters accumulate known CVEs in the control plane and kubelet over time. Leaving the upgrade channel unset (`"none"`) means the cluster's Kubernetes version only changes when someone manually triggers an upgrade — in practice this is frequently neglected, resulting in clusters running versions that are out of support and missing security patches, sometimes for years. An automatic upgrade channel (`patch`, `stable`, `rapid`, or `node-image`) ensures the cluster keeps pace with vendor-released security and stability fixes without relying on manual operational diligence, which is a baseline expectation for any AKS cluster running production workloads.

## How Checkov evaluates this
- **Terraform** (`AKSUpgradeChannel`): checks whether `automatic_channel_upgrade` is set and not equal to `"none"`, OR whether `automatic_upgrade_channel` is set and not equal to `"none"`. If either condition holds, the check **PASSES**; if neither attribute is set (or both are `"none"`), it **FAILS**.
- **ARM**: inspects `properties.autoUpgradeProfile.upgradeChannel` and **FAILS** if the value is `"none"` (also treating a missing block as a failure, via `missing_block_result=FAILED`).

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  name                = "myAksCluster"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "myaks"
  # automatic_channel_upgrade not set -> no scheduled upgrades

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediated example
```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  name                       = "myAksCluster"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  dns_prefix                 = "myaks"
  automatic_channel_upgrade  = "stable"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Set `automatic_channel_upgrade` to one of `patch`, `stable`, `rapid`, or `node-image` based on your risk tolerance (`stable` is a reasonable default balancing currency and stability).
2. If using an older provider version that only exposes `automatic_upgrade_channel`, set that attribute instead.
3. Pair the upgrade channel with a defined `maintenance_window` / `maintenance_window_auto_upgrade` block so upgrades happen during an approved, low-traffic time.
4. Test upgrade impact in a non-production cluster first — automatic upgrades can occasionally introduce breaking API changes between minor Kubernetes versions.
5. Note that `automatic_channel_upgrade` governs control-plane/Kubernetes version upgrades; node OS image patching may need to be configured separately (`node_os_channel_upgrade`) depending on provider version.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSUpgradeChannel.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AKSUpgradeChannel.py
- Microsoft Docs: https://learn.microsoft.com/en-us/azure/aks/auto-upgrade-cluster
