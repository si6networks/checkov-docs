# CKV2_AZURE_39: Ensure Azure VM is not configured with public IP and serial console access

## Severity
**HIGH** (score: 7.5/10)

Combining a public IP with unguarded serial console access on a VM broadens the internet-facing attack surface with an out-of-band management pathway that bypasses normal network-layer controls like NSGs and firewalls.

## Summary
This check flags Azure virtual machines that have both a public IP address attached to their network interface and no boot diagnostics (serial console) configuration guarding that exposure, since the combination allows direct internet-facing serial console access alongside public network reachability.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based connection check)
- **Resource types:** `azurerm_network_interface` connected to `azurerm_linux_virtual_machine`, `azurerm_windows_virtual_machine`, or `azurerm_virtual_machine`

## Why it matters
Azure's serial console provides low-level, out-of-band text access to a VM's console — bypassing normal network-layer controls like NSGs and firewalls — and is gated by `boot_diagnostics` configuration. A VM that has a public IP address attached to its NIC is directly reachable from the internet. If that same VM also lacks boot diagnostics disabled/controlled, it increases the attack surface: combined with weak Azure AD/RBAC controls, an attacker who compromises a management identity could use serial console access to bypass SSH/RDP restrictions, NSG rules, or conditional access policies enforced at the network layer, gaining direct console access to a publicly exposed machine. The safest posture is to avoid combining public IP exposure with unrestricted console access — either remove the public IP (using a bastion/load balancer/private endpoint instead) or ensure boot diagnostics is explicitly configured to control this pathway.

## How Checkov evaluates this
Graph-based JSON policy joining `azurerm_network_interface` to VM resources. It evaluates to PASS under any of these conditions (top-level `or`):
1. **Fails only when:** the NIC is connected to one of the VM resource types, the NIC's `ip_configuration.public_ip_address_id` has length greater than 0 (a public IP is attached), **and** the connected VM resource has no `boot_diagnostics` block at all.
2. **Passes when:** `ip_configuration.public_ip_address_id` does not exist, OR its length is less than or equal to 0, OR it explicitly equals `null` — i.e., no public IP is attached to the NIC.

In short: FAIL only occurs when a NIC with a public IP is attached to a VM that has no `boot_diagnostics` block defined; any VM without a public IP passes regardless of console configuration.

## Non-compliant example
```hcl
resource "azurerm_public_ip" "example" {
  name                = "example-pip"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  allocation_method   = "Static"
}

resource "azurerm_network_interface" "example" {
  name                = "example-nic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.example.id
  }
}

resource "azurerm_linux_virtual_machine" "example" {
  name                = "example-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_B1s"
  admin_username      = "adminuser"
  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]
  # no boot_diagnostics block defined
}
```

## Remediated example
```hcl
resource "azurerm_linux_virtual_machine" "example" {
  name                = "example-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_B1s"
  admin_username      = "adminuser"
  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]

  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.diag.primary_blob_endpoint
  }
}
```
Alternatively, remove the public IP association from the NIC entirely (`public_ip_address_id = null`) and access the VM via Azure Bastion or a private network path.

## Remediation steps
1. Prefer removing public IP addresses from VM NICs; route access through Azure Bastion, a jump box, or a VPN/ExpressRoute private connection instead.
2. If a public IP is genuinely required, explicitly configure the `boot_diagnostics` block on the VM resource so Checkov's graph condition (and the underlying governance intent) is satisfied.
3. Pair this with NSG rules that restrict inbound access to only the necessary ports/source ranges — a public IP with an unrestrictive NSG is a much larger risk than the console setting alone.
4. Audit existing VMs for public IP + missing boot diagnostics combinations using `az vm boot-diagnostics get-boot-log` or Azure Resource Graph queries.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureVMconfigPublicIP_SerialConsoleAccess.json)
- [Azure Serial Console documentation](https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/serial-console-overview)
