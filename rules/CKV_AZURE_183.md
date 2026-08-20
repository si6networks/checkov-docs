# CKV_AZURE_183: Ensure that VNET uses local DNS addresses

## Severity
**MEDIUM** (score: 4.5/10)

Relying on external (non-local/on-premises) DNS servers for a VNET can route internal name-resolution traffic outside the trust boundary, weakening network segmentation and creating a potential interception or availability dependency on external infrastructure.

## Summary
This check ensures that any custom DNS server IP configured on a virtual network falls within the VNet's own address space, rather than pointing to an external/on-premises DNS server.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform (`azurerm` provider), ARM templates, Bicep (compiled to ARM)
- **Resource types:**
  - ARM: `Microsoft.Network/virtualNetworks`
  - Terraform: `azurerm_virtual_network`

## Why it matters
Configuring DNS servers whose IP addresses fall outside the VNet's own address space typically means resolution depends on an external network path — an on-premises DNS server reached over VPN/ExpressRoute, or a DNS server in another, unpeered network. This creates a hard dependency on cross-network connectivity purely for name resolution: if the VPN/ExpressRoute circuit degrades or the on-prem server is unreachable, DNS resolution for resources in the VNet fails even though the VNet itself is healthy and reachable from elsewhere. Microsoft's own guidance recommends using Azure Private DNS Zones or DNS servers located inside the VNet's address space for local traffic to avoid taking an availability dependency on external infrastructure.

## How Checkov evaluates this
**ARM:** Reads `properties.dhcpOptions.dnsServers` (a list of DNS IPs) and `properties.addressSpace.addressPrefixes` (a list of CIDR ranges) from the VNet resource. For each configured DNS server IP, it checks whether that IP falls inside any of the VNet's own address prefixes (`ip_address in ip_network`). If at least one DNS server IP is within the VNet's address space, the check PASSES. If DNS servers are configured but none of them are within any of the VNet's address prefixes, it FAILS. If the address range or IP is malformed (unparsable), the result is `UNKNOWN`. If no `dnsServers` are configured at all, the check PASSES (defaults to Azure-provided DNS).

**Terraform:** Same logic, but reads `dns_servers` and `address_space` directly from the `azurerm_virtual_network` resource body.

## Non-compliant example
```hcl
resource "azurerm_virtual_network" "example" {
  name                = "example-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  dns_servers = ["192.168.1.10", "192.168.1.11"]  # on-prem DNS, outside 10.0.0.0/16
}
```

## Remediated example
```hcl
resource "azurerm_virtual_network" "example" {
  name                = "example-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  dns_servers = ["10.0.0.4", "10.0.0.5"]  # DNS servers inside the VNet's own address space
}
```

## Remediation steps
1. Identify VNets whose `dns_servers` list contains IPs outside the `address_space` CIDR ranges.
2. Deploy DNS servers (or an Azure DNS Private Resolver inbound endpoint) inside the VNet's own address space, or within a peered VNet's space if that dependency is acceptable, and point `dns_servers` at those local addresses.
3. Where feasible, replace custom on-prem DNS forwarding with Azure Private DNS Zones for VNet-local name resolution, reducing dependency on cross-premises links entirely.
4. If cross-premises DNS truly is required (e.g. hybrid AD integration), consider deploying DNS forwarders/conditional forwarders inside the VNet that then relay to on-prem servers, so the VNet's direct dependency is on a local, redundant endpoint.
5. Changing `dns_servers` reapplies to attached NICs; validate name resolution and DHCP renewal on affected VMs after the change.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/VnetLocalDNS.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VnetLocalDNS.py
- [Azure Private DNS documentation](https://learn.microsoft.com/en-us/azure/dns/private-dns-overview)
