# CKV2_AZURE_23: Ensure Azure spring cloud is configured with Virtual network (Vnet)
## Severity
**MEDIUM** (score: 5.0/10)

Running Azure Spring Cloud without VNet integration removes network segmentation, increasing the attack surface for the app platform even though it does not by itself disable authentication or encryption.

## Summary
This check verifies that an Azure Spring Cloud (Azure Spring Apps) service — at any SKU tier above the free `B0` Basic tier — is deployed into a customer-owned Virtual Network via the service runtime subnet configuration.

## Applicability
**Checkov framework(s):** `arm`, `terraform`

- **IaC frameworks:** Terraform and ARM templates (graph-based checks, one implementation per framework)
- **Resource/entity types involved:** `azurerm_spring_cloud_service` (Terraform), `Microsoft.AppPlatform/Spring` (ARM)

## Why it matters
By default, Azure Spring Cloud runs in a Microsoft-managed network with public endpoints for its runtime components. Deploying without a customer VNet means application traffic, service discovery, and the Spring Cloud Config Server/Service Registry all traverse or are reachable over Microsoft's shared network boundary rather than the organization's own network perimeter. This prevents applying network security groups, forced tunneling, private DNS, or network-level segmentation between the Spring Cloud runtime and other internal systems (databases, secrets stores, internal APIs). For workloads handling sensitive data or subject to network-isolation compliance requirements, running outside a VNet means the organization cannot enforce its usual network controls (firewalling, traffic inspection, private connectivity to other Azure resources) around the application runtime.

## How Checkov evaluates this
This is a **graph-based attribute check** with an SKU-tier exemption:
1. The resource's `sku.name` (ARM) / `sku_name` (Terraform) must **not equal** (case-insensitive) `B0` — the free/basic tier that does not support VNet injection is exempted from this requirement entirely.
2. For all other SKUs, the `properties.networkProfile.serviceRuntimeSubnetId` (ARM) / `network.service_runtime_subnet_id` (Terraform) attribute must exist — i.e., a subnet ID must actually be configured for the service runtime network profile.

If the SKU is not `B0` and no service runtime subnet ID is set, the resource FAILS.

## Non-compliant example
```hcl
resource "azurerm_spring_cloud_service" "example" {
  name                = "example-springcloud"
  resource_group_name = "example-rg"
  location            = "eastus"
  sku_name            = "S0"

  # No `network` block — Spring Cloud runs on Microsoft's shared network.
}
```

## Remediated example
```hcl
resource "azurerm_virtual_network" "example" {
  name                = "example-vnet"
  location            = "eastus"
  resource_group_name = "example-rg"
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "runtime" {
  name                 = "spring-cloud-runtime-subnet"
  resource_group_name  = "example-rg"
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "cluster" {
  name                 = "spring-cloud-cluster-subnet"
  resource_group_name  = "example-rg"
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_spring_cloud_service" "example" {
  name                = "example-springcloud"
  resource_group_name = "example-rg"
  location            = "eastus"
  sku_name            = "S0"

  # Added: network block pinning the runtime into the customer VNet.
  network {
    app_subnet_id                = azurerm_subnet.cluster.id
    service_runtime_subnet_id    = azurerm_subnet.runtime.id
    cidr_ranges                  = ["10.4.0.0/16", "10.5.0.0/16", "10.3.0.1/16"]
  }
}
```

## Remediation steps
1. Provision (or identify) a Virtual Network with two dedicated, non-overlapping subnets: one for the app runtime and one for the service runtime, as required by Azure Spring Apps VNet injection.
2. Add a `network` block to the `azurerm_spring_cloud_service` (or `networkProfile.serviceRuntimeSubnetId` in ARM) referencing the service runtime subnet.
3. If already deployed without a VNet, note that adding VNet injection to an existing Spring Cloud service typically requires **recreating the service** — this is not an in-place update; plan for downtime/migration.
4. Ensure the subnets meet Azure's minimum size requirements (`/24` recommended) and that required NSG/UDR rules for Spring Cloud's control-plane dependencies are in place per Microsoft's VNet injection documentation.
5. This requirement does not apply to the `B0` (Basic/free) SKU, which cannot use VNet injection — upgrade the SKU if network isolation is required.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureSpringCloudConfigWithVnet.json)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/graph_checks/AzureSpringCloudConfigWithVnet.json)
- [Deploy Azure Spring Apps in a virtual network](https://learn.microsoft.com/en-us/azure/spring-apps/how-to-deploy-in-azure-virtual-network)
