# CKV2_AZURE_49: Ensure that Azure Machine learning workspace is not configured with overly permissive network access

## Severity
**HIGH** (score: 7.5/10)

Leaving public network access enabled on an Azure Machine Learning workspace broadens network exposure of a service that holds training data, models, and credentials to potential internet-facing attacks.

## Summary
This check ensures an Azure Machine Learning workspace has public network access disabled, requiring access via private networking rather than the open internet.

## Applicability
**Checkov framework(s):** `arm`, `terraform`

- **IaC frameworks:** Terraform, ARM/Bicep (both graph-based checks)
- **Resource types:** `Microsoft.MachineLearningServices/workspaces` (ARM/Bicep), `azurerm_machine_learning_workspace` (Terraform)

## Why it matters
Azure Machine Learning workspaces orchestrate training jobs, host compute instances/clusters, and connect to datastores that often contain sensitive training data, model artifacts, and credentials for downstream services. A workspace with public network access enabled is reachable from the internet, expanding the attack surface for credential-stuffing against workspace authentication, exploitation of any workspace/API vulnerability, and unauthorized data exfiltration if an identity is compromised. ML workspaces frequently have broad permissions to storage accounts, key vaults, and container registries (via their managed identity), so a compromised or overly exposed workspace can become a pivot point to much more sensitive resources. Disabling public network access and requiring private endpoint connectivity confines access to your VNet, dramatically reducing exposure.

## How Checkov evaluates this
Graph-based JSON policy. PASSES when either:
- The `publicNetworkAccess` / `public_network_access_enabled` attribute does not exist (in ARM, absence is treated as compliant — though be aware actual Azure default behavior may differ from the check's assumption; always verify effective service behavior), **or**
- It is explicitly set to `"Disabled"` (ARM: `properties.publicNetworkAccess`) or `"false"` (Terraform: `public_network_access_enabled`).

FAILS when the attribute is explicitly set to enable public access (`"Enabled"` in ARM, or `true` in Terraform).

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

  public_network_access_enabled = true
}
```

## Remediated example
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

  public_network_access_enabled = false   # requires private endpoint / VNet access
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess = "Disabled"` (ARM/Bicep) on the ML workspace.
2. Provision an `azurerm_private_endpoint` (or equivalent ARM private endpoint resource) targeting the workspace so authorized VNet-connected clients (e.g., Azure ML compute instances, data scientists via VPN/Bastion) can still reach it.
3. Ensure associated resources — storage account, key vault, container registry — also have their network access restricted consistently, otherwise the workspace's dependencies remain exposed even if the workspace itself is locked down.
4. Test that CI/CD pipelines, notebooks, and SDK-based access all route through the private network path before enforcing this in production, since disabling public access breaks any client connecting over the public internet.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureMLWorkspacePublicNetwork.json)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/graph_checks/AzureMLWorkspacePublicNetwork.json)
- [Azure Machine Learning: Private Link documentation](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-configure-private-link)
