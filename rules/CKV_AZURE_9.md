# CKV_AZURE_9: Ensure that RDP access is restricted from the internet
## Severity
**HIGH** (score: 7.5/10)

An NSG rule that allows RDP (port 3389) from the internet exposes a remote administrative interface to brute-force and credential-stuffing attacks that can lead directly to full host compromise.

## Summary
This check flags Azure Network Security Group (NSG) rules that allow unrestricted inbound RDP (TCP port 3389) access from the public internet.

## Applicability
- **Terraform**: `azurerm_network_security_group` (inline `security_rule` blocks), `azurerm_network_security_rule` (standalone rule resources)
- **ARM templates**: `Microsoft.Network/networkSecurityGroups`, `Microsoft.Network/networkSecurityGroups/securityRules`
- **Bicep**: resources compiling to the above ARM types

## Why it matters
RDP (port 3389) is the standard protocol for remotely administering Windows servers, and it is one of the most commonly scanned and attacked ports on the internet. Leaving inbound RDP open to `0.0.0.0/0`, `Internet`, or `*` exposes the VM to:
- Continuous automated brute-force and credential-stuffing attacks against Windows logins from botnets scanning the entire IPv4 space for port 3389.
- Exploitation of RDP protocol vulnerabilities (e.g. BlueKeep-class remote code execution flaws) before patches are applied.
- A direct path for ransomware operators, who very commonly gain initial access to a network specifically via exposed RDP, to compromise a host and pivot laterally into the rest of the environment.

Restricting the source range to specific known IPs (or requiring a VPN/bastion/Azure Bastion) removes RDP as an internet-facing attack surface entirely, forcing any RDP session to originate from a trusted network path.

## How Checkov evaluates this
This check is a thin subclass of the shared `NSGRulePortAccessRestricted` base check, parameterized with `port=3389`. The underlying logic inspects each NSG security rule and FAILS when **all** of the following hold:
- `direction` (or `access`/`direction` combination) is `Inbound`
- `access` is `Allow`
- `protocol` is `TCP` (or `*`)
- the `destination_port_range` (or one of `destination_port_ranges`) includes port 3389 (either as an exact match, a range containing it, or a wildcard `*`)
- the `source_address_prefix` (or one of `source_address_prefixes`) is a wildcard/internet-wide value such as `*`, `0.0.0.0/0`, `<nw>/0`, or the Azure service tag `Internet`

If the source is scoped to a specific CIDR range (not a "any source" wildcard) or the port range excludes 3389, the rule PASSES.

## Non-compliant example
```hcl
resource "azurerm_network_security_group" "example" {
  name                = "example-nsg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  security_rule {
    name                       = "AllowRDP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"        # <-- open to the entire internet
    destination_address_prefix = "*"
  }
}
```

## Remediated example
```hcl
resource "azurerm_network_security_group" "example" {
  name                = "example-nsg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  security_rule {
    name                       = "AllowRDP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "203.0.113.10/32"  # <-- restricted to a known admin IP
    destination_address_prefix = "*"
  }
}
```

## Remediation steps
1. Identify the NSG rules that allow inbound access on port 3389 (or a range that includes it).
2. Replace any wildcard `source_address_prefix`/`source_address_prefixes` (`*`, `0.0.0.0/0`, `Internet`) with a specific, minimal CIDR range for known administrative source IPs (VPN gateway range, jump-box IP, or corporate egress IP).
3. Prefer eliminating direct RDP exposure altogether by using **Azure Bastion** or a VPN gateway for remote administration instead of a public-facing NSG allow rule.
4. If different admins need access from varying locations, consider Just-In-Time (JIT) VM access via Microsoft Defender for Cloud, which opens the port only for a limited time window per request.
5. Re-apply and verify existing administrative workflows still function against the new restricted source range before considering the change complete.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleRDPAccessRestricted.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/NSGRuleRDPAccessRestricted.py
