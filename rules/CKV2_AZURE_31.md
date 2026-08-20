# CKV2_AZURE_31: Ensure VNET subnet is configured with a Network Security Group (NSG)
## Severity
**HIGH** (score: 7.5/10)

A subnet with no Network Security Group has no layer-3/4 traffic filtering, leaving all resources placed in it open to unrestricted lateral and inbound network traffic within the VNet and beyond.

## Summary
This check verifies that an Azure Virtual Network subnet has an associated Network Security Group, with built-in exceptions for special-purpose subnets that either don't support NSGs or are exempt by convention.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check)
- **Resource type involved:** `azurerm_subnet`

## Why it matters
A subnet without an NSG has no network-layer traffic filtering applied at the subnet boundary — all inbound/outbound traffic to resources in that subnet is governed only by whatever NSGs (if any) are attached at the NIC level, or by nothing at all. This removes a foundational, centrally-manageable layer of network segmentation: without a subnet-level NSG, there's no consistent enforcement of least-privilege network access for every resource later placed in that subnet, and a resource deployed without its own NIC-level NSG is effectively unprotected by any Azure-native firewall. Subnet-level NSGs are a cheap, durable control that ensures new resources inherit a security baseline automatically rather than depending on every individual resource being separately hardened.

## How Checkov evaluates this
This is a **graph-based** check combining a connection requirement with several explicit exemptions (OR'd together — any one satisfies the check):
1. **Primary condition:** the `azurerm_subnet` must have a graph connection to either an `azurerm_network_security_group` or an `azurerm_subnet_network_security_group_association` resource.
2. **Exemption — GatewaySubnet:** if the subnet's `name` equals (case-insensitive) `"GatewaySubnet"`, it passes regardless of NSG association (Azure VPN/ExpressRoute gateway subnets do not support NSGs).
3. **Exemption — AzureFirewallSubnet:** if the subnet's `name` equals (case-insensitive) `"AzureFirewallSubnet"`, it passes (Azure Firewall subnets do not support NSGs either).
4. **Exemption — NetApp delegation:** if the subnet has a delegation with `service_delegation.name` equal to `"Microsoft.Netapp/volumes"` (case-insensitive), it passes (NetApp-delegated subnets have their own network handling).

Any subnet not matching one of these four conditions FAILS.

## Non-compliant example
```hcl
resource "azurerm_virtual_network" "example" {
  name                = "example-vnet"
  location            = "eastus"
  resource_group_name = "example-rg"
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "example" {
  name                 = "app-subnet"
  resource_group_name  = "example-rg"
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.1.0/24"]

  # No NSG or association resource references this subnet.
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

resource "azurerm_subnet" "example" {
  name                 = "app-subnet"
  resource_group_name  = "example-rg"
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_security_group" "example" {
  name                = "app-subnet-nsg"
  location            = "eastus"
  resource_group_name = "example-rg"

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Added: associate the NSG with the subnet.
resource "azurerm_subnet_network_security_group_association" "example" {
  subnet_id                 = azurerm_subnet.example.id
  network_security_group_id = azurerm_network_security_group.example.id
}
```

## Remediation steps
1. Create an `azurerm_network_security_group` with rules matching the intended traffic policy for the subnet (default-deny inbound, explicit allow rules for required ports/sources).
2. Associate it with the subnet via an `azurerm_subnet_network_security_group_association` resource (or inline via the `azurerm_network_security_group.subnet_ids` — note the association resource is the more commonly recommended, drift-safe approach).
3. Skip this remediation for `GatewaySubnet`, `AzureFirewallSubnet`, and subnets delegated to `Microsoft.Netapp/volumes` — Azure does not support attaching NSGs to these regardless of Terraform configuration.
4. Review existing NIC-level NSGs, if any, to ensure the new subnet-level NSG doesn't conflict with or duplicate rules unexpectedly (both apply simultaneously; a packet must be allowed by both to pass).
5. Test connectivity after applying default-deny rules — instrument monitoring/NSG flow logs to catch unintended traffic blocks before they affect production.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureSubnetConfigWithNSG.json)
- [Network security groups](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
