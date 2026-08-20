# CKV_AZURE_226: Ensure ephemeral disks are used for OS disks
## Severity
**MEDIUM** (score: 5.0/10)

Non-ephemeral AKS OS disks persist and replicate node-local temporary data to Azure Storage, creating a moderate data-remnant exposure risk for potentially sensitive workload data rather than a directly exploitable path.

## Summary
Ensures that AKS (Azure Kubernetes Service) node pools use ephemeral OS disks — local VM storage — rather than network-attached managed disks for their operating system disk.

## Applicability
- **Terraform**: `azurerm_kubernetes_cluster` — inspects `default_node_pool[0].os_disk_type`
- **ARM**: `Microsoft.ContainerService/managedClusters` — inspects `properties.agentPoolProfiles[0].osDiskType`
- **Bicep**: compiles to the ARM resource type above

## Why it matters
By default, AKS nodes use managed OS disks, which are network-attached storage that Azure automatically and continuously replicates to Azure Storage to protect against data loss if the underlying VM host needs to be relocated. For container workloads, this replication is largely wasted effort: containers are designed to be stateless with respect to the node's OS disk, and any data that does need persisting should be on a mounted persistent volume, not the OS disk itself. This constant background replication of the (largely disposable) OS disk contents introduces avoidable I/O overhead, slower node provisioning, and higher read/write latency for node-local operations — all without providing meaningful security or reliability benefit for typical Kubernetes workloads. Beyond performance, ephemeral disks also reduce the risk of sensitive temporary data (secrets cached to disk, temp files, container layer data) being durably persisted in Azure Storage where it could outlive the node's lifecycle and potentially be recovered by someone with access to the storage backend — ephemeral disk contents are discarded when the VM is deallocated/reimaged. Using ephemeral disks also enables faster cluster scale and upgrade operations because node re-imaging and boot are quicker without the managed-disk network dependency.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` with expected value `"Ephemeral"`.
- **Terraform**: inspects `default_node_pool/[0]/os_disk_type`. **PASSES** only if set to `"Ephemeral"`; **FAILS** if `"Managed"` (the default) or unset.
- **ARM**: inspects `properties/agentPoolProfiles/[0]/osDiskType`. Same pass/fail logic.

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
    # os_disk_type left unset -> defaults to "Managed"
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
    name         = "default"
    node_count   = 3
    vm_size      = "Standard_D4s_v5"
    os_disk_type = "Ephemeral"   # use local VM storage for the OS disk
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Set `os_disk_type = "Ephemeral"` on the `default_node_pool` block (and on any additional `azurerm_kubernetes_cluster_node_pool` resources).
2. Verify the selected `vm_size` has sufficient local (temp) disk capacity to host the ephemeral OS disk — the VM's cache/temp disk size must be at least as large as the requested OS disk size; not all VM SKUs support ephemeral OS disks, and Azure will reject the deployment if the SKU/size combination is incompatible.
3. This setting can typically only be applied at node pool creation — changing an existing node pool from Managed to Ephemeral generally requires creating a new node pool and migrating workloads (cordon/drain old nodes), rather than an in-place update.
4. Confirm no workloads rely on data surviving on the node's OS disk across a VM reimage/reallocation — ephemeral disks are wiped on such events, so anything needing persistence must use a PersistentVolume backed by Azure Disk/Files, not local node storage.
5. Factor in that ephemeral disk capacity consumes the VM's local temp storage, which may also be used by other node-local features (e.g., kubelet image cache) — size accordingly.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AKSEphemeralOSDisks.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSEphemeralOSDisks.py
- Azure docs: https://learn.microsoft.com/en-us/azure/aks/concepts-storage#ephemeral-os
