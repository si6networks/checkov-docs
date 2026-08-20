# CKV_AZURE_227: Ensure that the AKS cluster encrypt temp disks, caches, and data flows between Compute and Storage resources
## Severity
**HIGH** (score: 7.5/10)

Without encryption at host, temp disks, disk caches, and data flowing between AKS compute and storage remain unencrypted at rest, risking exposure of sensitive workload data if the underlying storage is compromised or improperly disposed of.

## Summary
Ensures that AKS node pools have host-based encryption (encryption-at-host) enabled, encrypting temp disks and OS/data disk caches on the underlying VM host as well as the data flowing between compute and storage.

## Applicability
- **Terraform**: `azurerm_kubernetes_cluster`, `azurerm_kubernetes_cluster_node_pool` — inspects `enable_host_encryption` (also accepts the newer alias `host_encryption_enabled`)
- **ARM**: `Microsoft.ContainerService/managedClusters`, `Microsoft.ContainerService/managedClusters/agentPools` — inspects `properties.enableEncryptionAtHost` (path differs slightly depending on whether the resource is the cluster itself or a standalone agent pool)
- **Bicep**: compiles to the ARM resource types above

## Why it matters
Standard Azure disk encryption protects data at rest on managed OS/data disks, but by default it does not cover certain other data paths on the VM host: the node's local temp disk (used for scratch space, container layers, and swap-like operations) and the disk *cache* layer that sits between the VM and the storage service. Without host-based encryption, this cache and temp-disk data — which can transiently hold sensitive information such as decrypted application data, credentials cached by processes, or container filesystem layers — is stored and transmitted unencrypted at the host level. In multi-tenant or shared-hardware cloud environments, or in the event of physical media disposal/reuse by the cloud provider, unencrypted temp/cache data represents a residual exposure that platform-level disk encryption alone does not close. Enabling encryption at host ensures that data is encrypted at rest on the temp disk (with platform-managed keys) and that the OS/data disk cache is encrypted (with either platform- or customer-managed keys, depending on the underlying disk's encryption configuration), and additionally protects the data flow between Compute and Storage services end-to-end.

## How Checkov evaluates this
This check has custom logic (`scan_resource_conf`) rather than a simple value lookup, because the correct attribute location differs by resource type:
- For `azurerm_kubernetes_cluster`: checks inside `default_node_pool[0]` for either `enable_host_encryption == [True]` or `host_encryption_enabled == [True]`. If neither is true, **FAILS**.
- For `azurerm_kubernetes_cluster_node_pool` (a standalone additional node pool): checks the top-level `enable_host_encryption == [True]` or `host_encryption_enabled == [True]` directly on the resource. If neither is true, **FAILS**.
- **ARM**: for `Microsoft.ContainerService/managedClusters`, checks `properties.agentPoolProfiles[0].enableEncryptionAtHost`; for `Microsoft.ContainerService/managedClusters/agentPools`, checks `properties.enableEncryptionAtHost` directly. `missing_block_result=CheckResult.FAILED` — an absent attribute is a **FAIL**. Only an explicit `true` **PASSES**.

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D4s_v5"
    # enable_host_encryption left unset -> defaults to false
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediated example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  default_node_pool {
    name                   = "default"
    node_count             = 3
    vm_size                = "Standard_D4s_v5"
    enable_host_encryption = true   # encrypt temp disk, caches, and compute-storage data flow
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Set `enable_host_encryption = true` (or the equivalent `host_encryption_enabled = true` on newer provider versions) on both the `default_node_pool` block within `azurerm_kubernetes_cluster` and on any standalone `azurerm_kubernetes_cluster_node_pool` resources.
2. Encryption at Host must be registered/enabled as a feature at the subscription level first (`Microsoft.Compute` `EncryptionAtHost` feature) before it can be used by AKS node pools — enable this via `az feature register` (or the equivalent Azure Policy/portal step) prior to applying the Terraform/ARM change.
3. Verify the target `vm_size` supports encryption at host — not all VM SKUs do; check VM size capabilities before selecting a size for node pools requiring this setting.
4. This setting is generally only configurable at node pool creation time, so enabling it on an existing non-compliant node pool typically requires creating a new node pool with the setting enabled and migrating workloads (cordon/drain), rather than an in-place update.
5. Be aware of a modest performance overhead from host-level encryption and validate in a test cluster before rolling out broadly to production node pools.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AKSEncryptionAtHostEnabled.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSEncryptionAtHostEnabled.py
- Azure docs: https://learn.microsoft.com/en-us/azure/aks/enable-host-encryption
