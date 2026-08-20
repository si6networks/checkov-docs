# CKV_AZURE_144: Ensure that Public Access is disabled for Machine Learning Workspace
## Severity
**LOW** (score: 2.0/10)

Enabling public access on an Azure Machine Learning workspace exposes the workspace's compute, notebooks, and stored datasets/models directly to the internet, a broad network exposure of a service that often holds sensitive training data.

## Summary
This check ensures an Azure Machine Learning Workspace has public network access disabled, restricting workspace management and data-plane operations to private network connectivity only.

## Applicability
- **Terraform**: `azurerm_machine_learning_workspace` resource, attribute `public_network_access_enabled`.

## Why it matters
An ML workspace centralizes access to training data, model artifacts, compute resources, and often has managed identities with broad access to linked storage accounts, Key Vaults, and container registries. If the workspace's public endpoint is reachable from the internet, it becomes a target for credential-based attacks against workspace management APIs and increases the surface for exploiting any authentication/authorization weaknesses (e.g., overly broad Azure AD app registrations, leaked workspace keys used by SDKs/notebooks). Because ML workspaces frequently aggregate sensitive datasets (which may include regulated or proprietary data) and can trigger arbitrary compute jobs, unauthorized access could lead to data exfiltration, model theft, or abuse of the linked compute/billing resources. Disabling public access and requiring private endpoint connectivity confines workspace interaction to your controlled network perimeter.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` treating `True` as a forbidden value for `public_network_access_enabled`. Notably it is constructed with `missing_attribute_result=CheckResult.FAILED` — meaning if the attribute is not set at all in the Terraform configuration, the check explicitly FAILS (fail-closed), rather than assuming the provider's default. It PASSES only when `public_network_access_enabled` is explicitly set to `false`.

## Non-compliant example
```hcl
resource "azurerm_machine_learning_workspace" "example" {
  name                    = "example-mlw"
  location                = azurerm_resource_group.example.location
  resource_group_name     = azurerm_resource_group.example.name
  application_insights_id = azurerm_application_insights.example.id
  key_vault_id            = azurerm_key_vault.example.id
  storage_account_id      = azurerm_storage_account.example.id

  identity {
    type = "SystemAssigned"
  }
  # public_network_access_enabled not set -- FAILS (missing_attribute_result = FAILED)
}
```

## Remediated example
```hcl
resource "azurerm_machine_learning_workspace" "example" {
  name                    = "example-mlw"
  location                = azurerm_resource_group.example.location
  resource_group_name     = azurerm_resource_group.example.name
  application_insights_id = azurerm_application_insights.example.id
  key_vault_id            = azurerm_key_vault.example.id
  storage_account_id      = azurerm_storage_account.example.id

  public_network_access_enabled = false  # explicitly disables public endpoint access

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Explicitly set `public_network_access_enabled = false` — do not rely on omitting the attribute, since this check treats a missing value as a failure by design (unlike most value-based checks).
2. Provision a private endpoint (`azurerm_private_endpoint`) for the workspace and configure the required private DNS zones (`privatelink.api.azureml.ms`, `privatelink.notebooks.azure.net`, etc.) so Studio, SDK, and CLI access resolve privately.
3. Ensure linked resources (storage account, Key Vault, container registry) are also configured for private connectivity/firewall rules consistent with the workspace, or the workspace may fail to reach them once its own network posture tightens.
4. Test access from all expected consumer networks (data scientist workstations via VPN/ExpressRoute, CI/CD compute, compute instances/clusters) before rolling this out broadly, since it is a breaking change for anyone previously reaching the workspace over the public internet.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MLPublicAccess.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/machine-learning/how-to-configure-private-link
