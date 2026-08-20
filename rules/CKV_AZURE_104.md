# CKV_AZURE_104: Ensure that Azure Data factory public network access is disabled
## Severity
**HIGH** (score: 7.0/10)

Allowing public network access to Data Factory exposes an orchestration service that can read/write connected data stores and run pipelines, widening the attack surface for a highly privileged component.

## Summary
This check ensures that an Azure Data Factory instance's public network access is disabled, so the factory's management endpoint can only be reached through a private endpoint rather than the public internet.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_data_factory` (inspects `public_network_enabled`)
- **ARM/Bicep**: `Microsoft.DataFactory/factories` (inspects `properties/publicNetworkAccess`)

## Why it matters
Azure Data Factory orchestrates data movement and transformation, frequently with linked services holding credentials or managed-identity access to sensitive data stores (SQL databases, storage accounts, Key Vault). Leaving the factory's public network access enabled exposes its management/API surface to the internet, increasing the risk of unauthorized access attempts, reconnaissance, and exploitation of any authentication weaknesses (leaked credentials, overly permissive RBAC) from any external network. Disabling public network access and requiring Private Link/VNet integration ensures the control plane is reachable only from within the trusted network perimeter, consistent with a defense-in-depth approach for a service that often has broad downstream data access.

## How Checkov evaluates this
- **Terraform**: inspects `public_network_enabled` on `azurerm_data_factory`. The check expects this to be `false`; if `true` (the provider default) or unset, the check **FAILS**.
- **ARM**: inspects `properties/publicNetworkAccess` and expects the string `"Disabled"`. Any other value (including the default `"Enabled"`) **FAILS**.

## Non-compliant example
```hcl
resource "azurerm_data_factory" "bad_example" {
  name                = "bad-datafactory"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  public_network_enabled = true
}
```

## Remediated example
```hcl
resource "azurerm_data_factory" "good_example" {
  name                = "good-datafactory"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  # Fix: disable public network access; require private endpoint connectivity
  public_network_enabled = false
}

resource "azurerm_private_endpoint" "adf_pe" {
  name                = "adf-private-endpoint"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "adf-privatelink"
    private_connection_resource_id = azurerm_data_factory.good_example.id
    subresource_names              = ["dataFactory"]
    is_manual_connection           = false
  }
}
```

## Remediation steps
1. Set `public_network_enabled = false` (Terraform) or `properties.publicNetworkAccess = "Disabled"` (ARM/Bicep) on the Data Factory resource.
2. Create a Private Endpoint targeting the `dataFactory` sub-resource so the authoring/management plane remains reachable from within the VNet.
3. If self-hosted Integration Runtimes need to reach the factory, ensure they run inside (or have private connectivity to) the same VNet.
4. Update DNS to resolve the factory's endpoint via the associated private DNS zone (`privatelink.datafactory.azure.net`).
5. Test the Data Factory authoring UI/Git integration and pipeline triggers after disabling public access, since some workflows (e.g., browser-based authoring from outside the VNet) may require a jump host or VPN.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/DataFactoryNoPublicNetworkAccess.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataFactoryNoPublicNetworkAccess.py)
- [Azure docs: Data Factory private endpoints](https://learn.microsoft.com/en-us/azure/data-factory/data-factory-private-link)
