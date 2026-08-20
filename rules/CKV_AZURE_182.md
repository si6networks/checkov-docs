# CKV_AZURE_182: Ensure that VNET has at least 2 connected DNS Endpoints

## Severity
**LOW** (score: 2.5/10)

A single DNS server configuration is a resiliency/single-point-of-failure issue for name resolution, not a direct confidentiality or access-control exposure.

## Summary
This check ensures a virtual network (or network interface) is configured with more than one custom DNS server, rather than a single one, to avoid a DNS single point of failure.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform (`azurerm` provider), ARM templates, Bicep (compiled to ARM)
- **Resource types:**
  - ARM: `Microsoft.Network/networkInterfaces`, `Microsoft.Network/virtualNetworks`
  - Terraform: `azurerm_virtual_network`, `azurerm_virtual_network_dns_servers`

## Why it matters
When a VNet or NIC is configured with exactly one custom DNS server address, that server becomes a single point of failure for name resolution across the entire network. If that DNS server becomes unreachable (maintenance, network partition, VM failure, misconfiguration), every resource depending on it for name resolution can lose the ability to resolve internal or external hostnames — breaking application connectivity, service discovery, certificate validation, and more, even though the network fabric itself is healthy. This is a resilience/availability control: requiring at least two DNS endpoints (ideally on separate infrastructure) provides redundancy so a single DNS outage does not cascade into a broader outage.

## How Checkov evaluates this
**ARM (`VnetSingleDNSServer.py`):** Looks at `properties.dnsSettings.dnsServers` (for NICs) or `properties.dhcpOptions.dnsServers` (for VNets). If that list exists and contains exactly one entry, the check FAILS. If it has zero, two, or more entries, or the field is absent, the check PASSES.

**Terraform (`VnetSingleDNSServer.py`):** Looks at the `dns_servers` attribute of `azurerm_virtual_network` / `azurerm_virtual_network_dns_servers`. If the list has exactly one entry, it FAILS; otherwise PASSES (including when no `dns_servers` are configured at all, which means Azure-provided DNS is used rather than a custom single server).

## Non-compliant example
```hcl
resource "azurerm_virtual_network" "example" {
  name                = "example-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  dns_servers = ["10.0.0.4"]  # single DNS server -> single point of failure
}
```

## Remediated example
```hcl
resource "azurerm_virtual_network" "example" {
  name                = "example-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  dns_servers = ["10.0.0.4", "10.0.0.5"]  # two redundant DNS endpoints
}
```

## Remediation steps
1. Identify any VNet or NIC resources specifying `dns_servers` (Terraform) or `dnsServers`/`dhcpOptions` (ARM/Bicep) with only one address.
2. Add at least a second DNS server IP — either a second on-prem/DNS-forwarder VM, an Azure Private DNS Resolver endpoint, or a secondary Azure Firewall/DNS proxy instance, in a different fault/availability domain from the first.
3. Alternatively, remove the custom `dns_servers` setting entirely to fall back to Azure-provided DNS (168.63.129.16), which is inherently redundant, if custom DNS is not strictly required.
4. Changing `dns_servers` on a VNet is applied to attached NICs; validate that DHCP lease renewal on VMs picks up the new servers (may require a reboot on some OS configurations).

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/VnetSingleDNSServer.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VnetSingleDNSServer.py
- [Azure virtual network name resolution documentation](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-name-resolution-for-vms-and-role-instances)
