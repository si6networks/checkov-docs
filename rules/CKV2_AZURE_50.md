# CKV2_AZURE_50: Ensure Azure Storage Account storing Machine Learning workspace high business impact data is not publicly accessible

## Severity
**HIGH** (score: 7.5/10)

Public network access on a storage account backing a Machine Learning workspace explicitly flagged as handling High Business Impact data directly contradicts the organization's own sensitive-data designation, risking internet exposure of highly sensitive datasets and model artifacts.

## Summary
This check ensures that when an Azure Machine Learning workspace is flagged as handling "High Business Impact" (HBI) data, any storage account connected to that workspace has public network access disabled.

## Applicability
- **IaC framework:** Terraform (graph-based check)
- **Resource types:** `azurerm_machine_learning_workspace` connected to `azurerm_storage_account`

## Why it matters
Marking a Machine Learning workspace `high_business_impact = true` is an explicit organizational signal that the data it processes is sensitive enough to warrant reduced diagnostic data collection and heightened security controls (Microsoft's own HBI feature reduces telemetry stored by the service specifically because the data is considered sensitive). If the storage account backing that workspace — which holds datasets, model outputs, and experiment artifacts — remains publicly accessible, the HBI designation is undermined: the very data the organization identified as high-risk is left reachable over the public internet, contradicted by the storage layer's own network configuration. An attacker who obtains storage account credentials, a leaked SAS token, or exploits an accidental public container is far more likely to succeed against a publicly network-accessible account than one confined to a private network.

## How Checkov evaluates this
Graph-based JSON policy, PASSES under any of these (top-level `or`):
1. No `azurerm_machine_learning_workspace` resource exists in scope (the filter condition is trivially satisfied and the rule doesn't apply), **or**
2. The workspace's `high_business_impact` attribute equals `false` (not HBI, so the storage exposure requirement doesn't apply), **or**
3. The workspace is connected to an `azurerm_storage_account`, **and** that storage account's `public_network_access_enabled` equals `false`.

FAILS when a workspace has `high_business_impact = true` and its connected storage account either has `public_network_access_enabled = true` or leaves it unset (default is `true`, i.e., publicly accessible).

## Non-compliant example
```hcl
resource "azurerm_machine_learning_workspace" "example" {
  name                    = "example-mlworkspace"
  location                = azurerm_resource_group.example.location
  resource_group_name     = azurerm_resource_group.example.name
  application_insights_id = azurerm_application_insights.example.id
  key_vault_id            = azurerm_key_vault.example.id
  storage_account_id      = azurerm_storage_account.example.id

  identity {
    type = "SystemAssigned"
  }

  high_business_impact = true
}

resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # public_network_access_enabled left unset -> defaults to true
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  public_network_access_enabled = false   # required for HBI-designated ML workspaces
}
```

## Remediation steps
1. For any `azurerm_machine_learning_workspace` with `high_business_impact = true`, locate its connected `azurerm_storage_account`(s) and set `public_network_access_enabled = false`.
2. Provision a private endpoint for the storage account so the ML workspace's compute (which should itself be VNet-integrated) can still reach it.
3. Confirm the workspace's own network access is also restricted (see CKV2_AZURE_49) — locking down storage alone is insufficient if the workspace itself remains publicly reachable.
4. Re-evaluate whether `high_business_impact` is set appropriately; if data truly is high-impact, apply this and related controls (private endpoints, CMK encryption, restricted RBAC) consistently across all connected resources, not just storage.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureMLWorkspaceHBIPublicNetwork.json)
- [Azure Machine Learning: High business impact workspaces documentation](https://learn.microsoft.com/en-us/azure/machine-learning/concept-data-encryption)
