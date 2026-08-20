# CKV_AZURE_77: Ensure that UDP Services are restricted from the Internet

## Severity
**CRITICAL** (score: 9.0/10)

Unrestricted UDP access from the internet to network security groups can expose services such as DNS, SNMP, or custom UDP protocols to reflection/amplification attacks and unauthenticated access from 0.0.0.0/0.

## Summary
This check ensures Azure Network Security Group (NSG) rules do not allow inbound UDP traffic from the entire internet (`*`, `0.0.0.0/0`, `Internet`, `any`, etc.).

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_network_security_group` (with inline `security_rule` blocks) and standalone `azurerm_network_security_rule`

## Why it matters
UDP is connectionless and widely abused for reflection/amplification DDoS attacks (DNS, NTP, memcached, SSDP) and for services that are frequently misconfigured with weak or no authentication (SNMP, syslog, custom telemetry protocols). An NSG rule that allows inbound UDP from any source directly exposes whatever UDP service is listening on the VM/subnet to the entire internet, letting attackers scan for open services, flood the target, or exploit UDP-based protocol vulnerabilities without the connection-establishment friction TCP provides. Restricting the source address prevents unauthenticated internet-wide reachability to these often-unauthenticated ports.

## How Checkov evaluates this
For each rule configuration (single-rule `azurerm_network_security_rule`, or one entry within a `security_rule` block of an `azurerm_network_security_group`), the check fails when ALL of the following are true simultaneously:
- `protocol` equals `udp` (case-insensitive)
- `direction` equals `inbound` (case-insensitive)
- `access` equals `allow` (case-insensitive)
- `source_address_prefix` is one of the recognized "internet" wildcard values (from `INTERNET_ADDRESSES`, e.g. `*`, `0.0.0.0/0`, `internet`, `any`)

If any of these conditions doesn't hold (e.g. protocol is TCP, or direction is outbound, or the rule denies access, or the source is a specific CIDR), the rule passes.

## Non-compliant example
```hcl
resource "azurerm_network_security_rule" "example" {
  name                        = "allow-udp-inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_range      = "161"
  source_address_prefix       = "*"           # entire internet
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.example.name
  network_security_group_name = azurerm_network_security_group.example.name
}
```

## Remediated example
```hcl
resource "azurerm_network_security_rule" "example" {
  name                        = "allow-udp-inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_range      = "161"
  source_address_prefix       = "10.20.0.0/24"   # restricted to a trusted network
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.example.name
  network_security_group_name = azurerm_network_security_group.example.name
}
```

## Remediation steps
1. Identify NSG rules with `protocol = "Udp"`, `direction = "Inbound"`, `access = "Allow"`, and a wildcard `source_address_prefix`.
2. Replace the wildcard source with the specific CIDR ranges, application security groups, or service tags that legitimately need access (e.g. a VPN gateway subnet, a partner's known IP range).
3. If the UDP service must remain internet-facing (e.g. a public game server, VoIP gateway), place it behind Azure DDoS Protection Standard and consider Azure Firewall/NVA-based filtering rather than a bare NSG allow-all.
4. Re-apply — NSG rule changes take effect immediately without resource downtime.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleUDPAccessRestricted.py
- Azure docs: https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview
