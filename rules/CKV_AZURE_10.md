# CKV_AZURE_10: Ensure that SSH access is restricted from the internet
## Severity
**CRITICAL** (score: 9.0/10)

An NSG rule that permits SSH (port 22) ingress from 0.0.0.0/0 exposes a remote administrative interface directly to the internet, enabling brute-force and credential-stuffing attacks against every reachable host.

## Summary
This check ensures that Azure Network Security Group (NSG) rules do not allow unrestricted inbound access to TCP port 22 (SSH) from the public internet.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_network_security_group`, `azurerm_network_security_rule`
- **ARM/Bicep**: `Microsoft.Network/networkSecurityGroups`, `Microsoft.Network/networkSecurityGroups/securityRules`

This is one member of Checkov's family of `NSGRulePortAccessRestricted`-derived checks; this instance is specialized for port 22.

## Why it matters
SSH is the primary remote-administration protocol for Linux hosts and is one of the most heavily scanned and attacked ports on the internet. An NSG rule that allows inbound traffic on port 22 from `*`, `Internet`, `0.0.0.0/0`, or `Any` exposes the management plane of every VM behind that NSG to automated credential-stuffing and brute-force attacks from anywhere in the world. If any instance behind the NSG has weak credentials, an exposed key, or an unpatched SSH daemon, an attacker who can reach it directly bypasses any need to compromise an intermediate host first. Restricting SSH ingress to specific known ranges (corporate VPN, bastion host, jump box) or requiring Azure Bastion/JIT access dramatically reduces the attack surface.

## How Checkov evaluates this
The check inherits from a shared `NSGRulePortAccessRestricted` base check, parameterized with `port=22`. It inspects each security rule's:
- **direction** — must be `Inbound` to be relevant,
- **access** — must be `Allow` to be relevant,
- **protocol** — must be `TCP` or `*`,
- **destination port range(s)** — must include port 22 (either as an exact match, a `*` wildcard, or a numeric range that contains 22),
- **source address prefix(es)** — the check **FAILS** if the source is a wildcard/unrestricted value such as `*`, `0.0.0.0/0`, `::/0`, `Internet`, or `Any`.

If the source is scoped to a specific CIDR range, tag other than `Internet`/`Any`, or the rule does not target port 22 at all, the check **PASSES**.

## Non-compliant example
```hcl
resource "azurerm_network_security_group" "bad_example" {
  name                = "bad-nsg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  security_rule {
    name                       = "allow-ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
```

## Remediated example
```hcl
resource "azurerm_network_security_group" "good_example" {
  name                = "good-nsg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  security_rule {
    name                       = "allow-ssh-from-corp-vpn"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    # Fix: restrict source to a known, trusted CIDR range instead of the internet
    source_address_prefix      = "203.0.113.0/24"
    destination_address_prefix = "*"
  }
}
```

## Remediation steps
1. Identify NSG rules with `direction = Inbound`, `access = Allow`, and a destination port covering 22.
2. Replace wildcard `source_address_prefix`/`source_address_prefixes` values (`*`, `0.0.0.0/0`, `Internet`, `Any`) with specific trusted CIDR ranges (office/VPN egress IPs, bastion subnet).
3. Prefer removing direct SSH ingress entirely and routing access through Azure Bastion or a hardened jump host in a management subnet.
4. If just-in-time (JIT) VM access via Microsoft Defender for Cloud is used instead of a static NSG rule, ensure the static "allow all" rule is removed so JIT is the only path.
5. Re-run `terraform plan`/`checkov` to confirm the rule no longer matches an unrestricted source.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/NSGRuleSSHAccessRestricted.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleSSHAccessRestricted.py)
- [Azure docs: Network security groups](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
- [Azure docs: Just-in-time VM access](https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-overview)
