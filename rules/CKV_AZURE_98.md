# CKV_AZURE_98: Ensure that Azure Container group is deployed into virtual network
## Severity
**LOW** (score: 2.0/10)

An Azure Container Instance group not deployed into a virtual network typically receives a public IP and lacks network segmentation, broadening the container's attack surface to the internet or other tenants.

## Summary
This check verifies that an Azure Container Instances (ACI) container group is deployed into a virtual network subnet rather than using default networking with a public/platform-managed IP.

## Applicability
- **Terraform**: `azurerm_container_group` (inspects `subnet_ids`)

## Why it matters
By default, an Azure Container Instance group can be assigned a public IP address directly, placing the container's network endpoint on the open internet without any network-layer isolation. Without VNet integration (`subnet_ids`):
- The container group cannot be protected by Network Security Groups, VNet-level firewall rules, or private routing — its exposure surface is governed only by whatever the container application itself does (or fails to do) for access control.
- It cannot communicate privately with other resources in your VNet (databases, internal APIs, etc.) without traversing the public internet or a public endpoint, increasing both attack surface and unnecessary data egress.
- It's incompatible with common enterprise network segmentation requirements that mandate all compute resources reside within a defined VNet/subnet boundary for traffic inspection, logging, and policy enforcement.

Deploying the container group into a VNet subnet lets you apply NSGs, route tables, and private connectivity to other VNet resources, keeping the container's network traffic inside your controlled network perimeter.

## How Checkov evaluates this
Uses `BaseResourceValueCheck` with `ANY_VALUE` as the expected value on the `subnet_ids` attribute — meaning it simply checks that `subnet_ids` is set to any non-empty value. If `subnet_ids` is absent, the check FAILS. Note: the check specifically targets `subnet_ids` (plural, the modern attribute) rather than the deprecated `network_profile_id`, since Azure deprecated `network_profile_id` for new container groups as of AzureRM provider v3.16.0+.

## Non-compliant example
```hcl
resource "azurerm_container_group" "example" {
  name                = "example-cg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  os_type             = "Linux"

  container {
    name   = "example-container"
    image  = "mcr.microsoft.com/azuredocs/aci-helloworld:latest"
    cpu    = "0.5"
    memory = "1.5"

    ports {
      port     = 80
      protocol = "TCP"
    }
  }
  # no subnet_ids -> uses default/public networking
}
```

## Remediated example
```hcl
resource "azurerm_subnet" "aci" {
  name                 = "aci-subnet"
  resource_group_name  = azurerm_resource_group.example.name
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.1.0/24"]

  delegation {
    name = "aci-delegation"
    service_delegation {
      name    = "Microsoft.ContainerInstance/containerGroups"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

resource "azurerm_container_group" "example" {
  name                = "example-cg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  os_type             = "Linux"

  container {
    name   = "example-container"
    image  = "mcr.microsoft.com/azuredocs/aci-helloworld:latest"
    cpu    = "0.5"
    memory = "1.5"

    ports {
      port     = 80
      protocol = "TCP"
    }
  }

  subnet_ids = [azurerm_subnet.aci.id]   # <-- deploys into a delegated VNet subnet
}
```

## Remediation steps
1. Create a dedicated subnet delegated to `Microsoft.ContainerInstance/containerGroups` (ACI requires an exclusively-delegated subnet — it cannot share a subnet with other resource types).
2. Set `subnet_ids = [azurerm_subnet.<name>.id]` on the `azurerm_container_group` resource.
3. If migrating an existing container group, note that `subnet_ids`/VNet association is typically an immutable, creation-time property — changing it usually requires recreating the container group.
4. Apply NSG rules on the delegated subnet to restrict inbound/outbound traffic as needed for the workload.
5. If you are currently using the deprecated `network_profile_id` attribute, plan a migration to `subnet_ids`, since `network_profile_id` support was removed from newer AzureRM provider versions.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureContainerGroupDeployedIntoVirtualNetwork.py
