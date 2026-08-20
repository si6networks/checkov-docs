# CKV_AZURE_142: Ensure Machine Learning Compute Cluster Local Authentication is disabled
## Severity
**LOW** (score: 2.0/10)

Leaving local authentication enabled on a Machine Learning Compute Cluster keeps a non-AAD credential path available for a workload that typically has more limited blast radius than a full data-plane database, so it's a real but somewhat narrower IAM weakness.

## Summary
This check ensures an Azure Machine Learning Compute Cluster has local (SSH/key-based) authentication disabled, requiring Azure AD-based identity for management access instead.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_machine_learning_compute_cluster` resource, attribute `local_auth_enabled`.

## Why it matters
Azure ML Compute Clusters can be configured to allow SSH access with local username/key credentials for direct node access. This local-auth path bypasses Azure AD authentication, Conditional Access, and MFA — anyone with the SSH key/credential can directly access compute nodes that may hold training data, model artifacts, credentials mounted for data access, or workspace secrets, without any Azure AD-tied audit trail. Since compute clusters process potentially sensitive datasets and have network/identity access configured for the ML workspace (e.g., via managed identity to storage, Key Vault), an attacker with local SSH access could exfiltrate training data, tamper with model outputs, or pivot using the compute's assigned identity/credentials. Disabling local authentication removes this side channel, forcing all administrative access through Azure AD-governed control planes.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting `local_auth_enabled`, expecting the value `False` to PASS. If the attribute is absent, the provider default (which for `azurerm_machine_learning_compute_cluster` is `true`, local auth enabled) applies, so the check FAILS by default; an explicit `false` PASSES.

## Non-compliant example
```hcl
resource "azurerm_machine_learning_compute_cluster" "example" {
  name                          = "example-cluster"
  location                      = azurerm_resource_group.example.location
  machine_learning_workspace_id = azurerm_machine_learning_workspace.example.id
  vm_priority                   = "LowPriority"
  vm_size                       = "STANDARD_DS2_V2"

  scale_settings {
    min_node_count                       = 0
    max_node_count                       = 1
    scale_down_nodes_after_idle_duration = "PT30S"
  }

  identity {
    type = "SystemAssigned"
  }
  # local_auth_enabled left at default (true) -- FAILS
}
```

## Remediated example
```hcl
resource "azurerm_machine_learning_compute_cluster" "example" {
  name                          = "example-cluster"
  location                      = azurerm_resource_group.example.location
  machine_learning_workspace_id = azurerm_machine_learning_workspace.example.id
  vm_priority                   = "LowPriority"
  vm_size                       = "STANDARD_DS2_V2"

  local_auth_enabled = false  # disables SSH/local credential access to compute nodes

  scale_settings {
    min_node_count                       = 0
    max_node_count                       = 1
    scale_down_nodes_after_idle_duration = "PT30S"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Set `local_auth_enabled = false` on `azurerm_machine_learning_compute_cluster` resources.
2. If your workflow currently relies on direct SSH access to compute nodes for debugging, transition to Azure ML's supported remote debugging/monitoring tools (e.g. Azure ML Studio job logs, VS Code remote via Azure ML compute instances with AAD auth) instead of raw SSH.
3. Confirm the compute cluster's managed identity has only the minimum necessary role assignments (e.g., storage/Key Vault access scoped to what training jobs require), since removing local auth does not reduce the identity's own permissions.
4. This is a compute-cluster-creation-time setting in some provider versions — check whether changing it on an existing cluster forces recreation in your `azurerm` provider version, and plan for potential downtime/redeployment of the compute target.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MLCCLADisabled.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/machine-learning/how-to-secure-training-vnet
