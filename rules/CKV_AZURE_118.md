# CKV_AZURE_118: Ensure that Network Interfaces disable IP forwarding
## Severity
**HIGH** (score: 7.5/10)

Enabled IP forwarding lets a compromised VM route and relay traffic between networks, undermining network segmentation and enabling lateral movement or traffic interception across VNets.

## Summary
This check verifies that Azure Network Interface (NIC) resources have IP forwarding disabled, preventing the attached VM from routing traffic that isn't addressed to itself.

## Applicability
- **IaC framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_network_interface`

## Why it matters
IP forwarding on a NIC tells Azure's networking stack to accept and forward packets whose destination IP does not match the NIC's own assigned address(es) — effectively allowing the attached VM to act as a router or NAT gateway for other traffic on the virtual network. Legitimate use cases exist (NVAs, VPN gateways, load balancers implemented as VMs), but when enabled unnecessarily on ordinary application/database VMs it significantly expands the blast radius of a single VM compromise: an attacker who gains code execution on that VM can then pivot traffic across network segments, bypass network security group boundaries designed around subnet isolation, or use the VM as a covert relay for traffic that should never have reached it. Because it's a network-layer setting rather than an OS setting, it's easy to enable inadvertently (e.g. copy-pasted from an NVA template) and easy to overlook during review, making it a common source of unintended lateral-movement pathways.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `enable_ip_forwarding` attribute:
- **PASS** if `enable_ip_forwarding` is `false`.
- **PASS** by default if the attribute is entirely omitted (`missing_block_result=CheckResult.PASSED` — the Azure default for this setting is `false`).
- **FAIL** if `enable_ip_forwarding` is explicitly set to `true`.

## Non-compliant example
```hcl
resource "azurerm_network_interface" "example" {
  name                = "nic-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  enable_ip_forwarding = true  # allows this VM to forward traffic not addressed to it

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
  }
}
```

## Remediated example
```hcl
resource "azurerm_network_interface" "example" {
  name                = "nic-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  enable_ip_forwarding = false  # disable IP forwarding unless this is a router/NVA

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
  }
}
```

## Remediation steps
1. Remove `enable_ip_forwarding = true` from the NIC, or set it explicitly to `false`.
2. If the VM genuinely needs to route/forward traffic (e.g. it's a network virtual appliance, VPN, or firewall appliance), leave the setting enabled but document the justification and ensure the NIC/subnet is isolated with strict NSG rules limiting what it can reach.
3. Also verify the guest OS itself doesn't have IP forwarding enabled at the kernel level (e.g. Linux `net.ipv4.ip_forward=1`), since disabling only the Azure-level flag isn't sufficient on its own for full defense-in-depth.
4. Applying this change to an existing NIC does not require replacement in most cases, but validate in a non-production environment since it changes live routing behavior for the attached VM.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NetworkInterfaceEnableIPForwarding.py)
- [Azure network interface IP forwarding documentation](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-network-interface-vm)
