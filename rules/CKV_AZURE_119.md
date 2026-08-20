# CKV_AZURE_119: Ensure that Network Interfaces don't use public IPs
## Severity
**HIGH** (score: 8.0/10)

A network interface with a public IP directly exposes the attached VM's services to the internet, bypassing intended network perimeter controls and significantly widening the attack surface.

## Summary
This graph-based check verifies that Azure Network Interface (NIC) resources are not directly associated with a Public IP Address resource, keeping the attached VM reachable only over private networking.

## Applicability
- **IaC framework:** Terraform (Azure provider)
- **Resource types:** `azurerm_network_interface` (checked for connections to `azurerm_public_ip`)

## Why it matters
Attaching a public IP directly to a VM's network interface exposes that VM's ports directly to the internet, subject only to whatever Network Security Group rules happen to be applied. This is a very common source of real-world breaches: a public IP on a NIC means any RDP/SSH/database port left open (intentionally, by default, or by NSG misconfiguration) is immediately scannable and attackable by internet-wide bots — this is exactly how many ransomware and cryptomining campaigns gain initial access to Azure VMs. The standard, defense-in-depth approach is to keep VMs on private IPs only and route any needed inbound access through a controlled ingress point (Azure Bastion, a load balancer, Application Gateway/WAF, or a VPN/ExpressRoute gateway) that provides centralized logging, authentication, and filtering — rather than depending on every VM owner correctly configuring NSGs.

## How Checkov evaluates this
This is a graph-based JSON policy that checks resource connections rather than a single attribute:
- It filters for resources of type `azurerm_network_interface`.
- **FAIL** if that NIC has a connection to any `azurerm_public_ip` resource (e.g. via `ip_configuration.public_ip_address_id` referencing the public IP resource's ID).
- **PASS** if no such connection exists — i.e., the NIC has no associated Public IP resource in the Terraform graph.

## Non-compliant example
```hcl
resource "azurerm_public_ip" "example" {
  name                = "pip-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  allocation_method   = "Static"
}

resource "azurerm_network_interface" "example" {
  name                = "nic-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.example.id  # directly internet-exposed
  }
}
```

## Remediated example
```hcl
resource "azurerm_network_interface" "example" {
  name                = "nic-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
    # no public_ip_address_id -> private-only, access via Bastion/LB/Gateway instead
  }
}
```

## Remediation steps
1. Remove the `public_ip_address_id` attribute from the NIC's `ip_configuration` block, and remove/repurpose the associated `azurerm_public_ip` resource if it isn't needed elsewhere.
2. For administrative access, deploy Azure Bastion in the VNet instead of exposing RDP/SSH publicly.
3. For application traffic, front the VM(s) with an `azurerm_lb` (Load Balancer) or `azurerm_application_gateway`, which can hold the public IP centrally while backend VMs stay private.
4. If a workload genuinely requires a direct public IP (e.g. a bastion/jump host itself), consider suppressing this check for that specific resource with a documented justification rather than disabling it globally.
5. Removing a public IP from a NIC can typically be done in-place but will interrupt any existing inbound connections to that address — plan for a maintenance window.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureNetworkInterfacePublicIPAddressId.json)
- [Azure public IP addresses documentation](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses)
