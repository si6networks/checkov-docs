# CKV_AZURE_160: Ensure that HTTP (port 80) access is restricted from the internet

## Severity
**HIGH** (score: 7.0/10)

Leaving HTTP port 80 open to the entire internet on an NSG exposes any bound service to unencrypted traffic interception and gives attackers an unrestricted, low-friction target for reconnaissance and exploitation.

## Summary
This check ensures that Azure Network Security Group (NSG) rules do not allow unrestricted inbound access on port 80 (HTTP) from the public internet.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, Bicep, ARM
- **Resource types:**
  - Terraform: `azurerm_network_security_group`, `azurerm_network_security_rule`
  - ARM/Bicep: `Microsoft.Network/networkSecurityGroups`, `Microsoft.Network/networkSecurityGroups/securityRules`

## Why it matters
Port 80 serves unencrypted HTTP traffic. Leaving it open to `Internet`/`*`/`0.0.0.0/0` on an NSG means any host on the internet can reach whatever service is bound to that port — commonly a web server or load balancer — over plaintext, exposing request/response data (including any tokens, cookies, or credentials sent before an HTTPS redirect completes) to interception, and giving attackers an easy, low-friction target for reconnaissance, exploitation of known web-server vulnerabilities, or credential harvesting via a fake HTTP endpoint. Even where port 80 is only meant to redirect to HTTPS, it should be scoped to intended sources (e.g. a load balancer or specific ranges) rather than the entire internet, minimizing the exposed footprint of the resource.

## How Checkov evaluates this
This check (`NSGRuleHTTPAccessRestricted`) is a thin subclass of the shared `NSGRulePortAccessRestricted` base check, instantiated with `port=80`. The base check inspects NSG security rules (whether defined inline within an `azurerm_network_security_group` or as standalone `azurerm_network_security_rule` / `Microsoft.Network/.../securityRules` resources) for:
- `direction == "Inbound"`
- `access == "Allow"`
- A `destination_port_range` (or range list) that includes port `80`
- A `source_address_prefix` (or `source_address_prefixes`) that is unrestricted — e.g. `*`, `0.0.0.0/0`, `Internet`, or `any`

If a rule matches all of the above, the check **FAILS**. Rules that restrict the source to specific CIDR ranges, tags other than `Internet`/`*` (e.g. `VirtualNetwork`, `AzureLoadBalancer`), or that don't cover port 80, **PASS**.

## Non-compliant example
```hcl
resource "azurerm_network_security_group" "example" {
  name                = "example-nsg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  security_rule {
    name                       = "Allow-HTTP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"      # unrestricted internet access
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
    name                       = "Allow-HTTP-From-LB"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "10.0.1.0/24"   # restricted to a known, trusted source
    destination_address_prefix = "*"
  }
}
```

## Remediation steps
1. Identify any NSG rule that allows inbound traffic from `*`, `0.0.0.0/0`, or `Internet` on port 80 (or a range covering it).
2. Restrict `source_address_prefix` / `source_address_prefixes` to specific, known CIDR ranges (e.g. a load balancer subnet, corporate VPN range) or an appropriate Azure service tag rather than the whole internet.
3. If port 80 is genuinely meant to be public (e.g. to redirect to HTTPS on a public web endpoint), consider placing an Azure Application Gateway/Front Door/WAF in front instead of a bare NSG-open port, and restrict the NSG to only the trusted upstream.
4. This is an in-place configuration change — no resource replacement required.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleHTTPAccessRestricted.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/NSGRuleHTTPAccessRestricted.py)
- [Azure Network Security Group documentation](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
