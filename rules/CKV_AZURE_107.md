# CKV_AZURE_107: Ensure that API management services use virtual networks
## Severity
**LOW** (score: 2.0/10)

Not placing API Management inside a virtual network removes network-layer segmentation and isolation controls for an API gateway that fronts backend services.

## Summary
This check ensures that an Azure API Management (APIM) service instance is deployed into a virtual network (VNet), rather than being deployed with no VNet integration at all.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_api_management` (inspects `virtual_network_configuration[0].subnet_id`)
- **ARM/Bicep**: `Microsoft.ApiManagement/service` (inspects `properties/virtualNetworkConfiguration`)

## Why it matters
API Management sits in front of backend APIs and often has network-level reachability to internal services, databases, and other backend systems that are not meant to be exposed directly to the internet. When APIM is deployed without VNet integration, both its control plane and (depending on network type) its data plane operate purely over public IP space with no ability to apply network security groups, route tables, or private connectivity to backends. Placing APIM inside a VNet (in either External or Internal mode) allows you to enforce NSG-based segmentation, keep backend connectivity private, and use Azure Firewall/UDRs to control egress — significantly reducing the blast radius if the APIM instance or its backends are targeted.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using the `ANY_VALUE` sentinel, meaning any non-empty value passes.
- **Terraform**: inspects `virtual_network_configuration[0].subnet_id`. If a subnet ID is present, the check **PASSES**; if the block/attribute is absent, it **FAILS**.
- **ARM**: inspects `properties/virtualNetworkConfiguration` with `missing_block_result=CheckResult.FAILED` — if the block is missing entirely, the check explicitly **FAILS** (rather than defaulting to pass); if present with any value, it **PASSES**.

## Non-compliant example
```hcl
resource "azurerm_api_management" "bad_example" {
  name                = "bad-apim"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  publisher_name      = "My Company"
  publisher_email     = "admin@example.com"

  sku_name = "Developer_1"

  # No virtual_network_configuration block -> no VNet integration
}
```

## Remediated example
```hcl
resource "azurerm_api_management" "good_example" {
  name                = "good-apim"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  publisher_name      = "My Company"
  publisher_email     = "admin@example.com"

  sku_name            = "Developer_1"
  virtual_network_type = "External"

  # Fix: integrate APIM with a VNet subnet
  virtual_network_configuration {
    subnet_id = azurerm_subnet.apim_subnet.id
  }
}
```

## Remediation steps
1. Add a `virtual_network_configuration` block referencing a dedicated subnet's `subnet_id`, and set `virtual_network_type` to `"External"` (internet-facing gateway with VNet-connected backends) or `"Internal"` (fully private, no public gateway) as appropriate.
2. Ensure the subnet is delegated/sized correctly per Azure's APIM subnet requirements (dedicated subnet, sufficient IP addresses, required NSG rules for the APIM control plane to management endpoints).
3. Note that this requires the `Developer`, `Basic`, `Standard`, or `Premium` SKU — VNet integration is not available on the `Consumption` tier.
4. Changing VNet configuration on an existing APIM instance can cause a period of downtime/redeployment; plan a maintenance window for production instances.
5. Configure NSGs on the APIM subnet to allow required management traffic (per Microsoft's documented rules) while restricting everything else.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/APIServicesUseVirtualNetwork.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIServicesUseVirtualNetwork.py)
- [Azure docs: Use a virtual network with Azure API Management](https://learn.microsoft.com/en-us/azure/api-management/virtual-network-concepts)
