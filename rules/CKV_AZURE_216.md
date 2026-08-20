# CKV_AZURE_216: Ensure DenyIntelMode is set to Deny for Azure Firewalls
## Severity
**HIGH** (score: 7.0/10)

Leaving Azure Firewall threat intelligence mode in Alert (instead of Deny) means traffic matched to known-malicious IPs/domains is only logged, not blocked, allowing confirmed threat-intel-flagged traffic through the perimeter.

## Summary
Ensures that a classic (non-Firewall-Policy-managed) Azure Firewall has its Threat Intelligence-based filtering mode set to `Deny` rather than `Alert` (or off), so traffic matching known-malicious IP addresses and domains is actually blocked instead of merely logged.

## Applicability
- **Terraform**: `azurerm_firewall` — inspects `threat_intel_mode`
- **ARM**: `Microsoft.Network/azureFirewalls` — inspects `properties.threatIntelMode`
- **Bicep**: compiles to the ARM resource type above

## Why it matters
Azure Firewall's Threat Intelligence feature cross-references traffic against Microsoft's threat intelligence feed, which contains known malicious IP addresses and domains associated with botnets, command-and-control infrastructure, and other attack sources. The feature supports two active modes: `Alert` (log a match but still allow the traffic through) and `Deny` (log the match and block the traffic). If the mode is left at `Alert` or disabled entirely, connections to/from known-bad infrastructure are permitted to complete — meaning malware call-outs to C2 servers, exfiltration to known bad-actor IPs, or inbound attacks from flagged sources are not actually stopped, only recorded after the fact (if anyone reviews the logs). This significantly weakens the firewall's effectiveness as a real-time defensive control and turns a preventive control into a purely detective one, delaying response and increasing the window during which a compromised host can communicate with attacker infrastructure.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` with a hard-coded expected value of `"Deny"`.
- **Terraform**: inspects `threat_intel_mode`. The check **PASSES** only when the value equals `"Deny"`; any other value (including `"Alert"`, `"Off"`, or being unset/default) **FAILS**.
- **ARM**: inspects `properties.threatIntelMode`. Same logic applies.

## Non-compliant example
```hcl
resource "azurerm_firewall" "example" {
  name                = "example-fw"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  threat_intel_mode   = "Alert"

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.example.id
    public_ip_address_id = azurerm_public_ip.example.id
  }
}
```

## Remediated example
```hcl
resource "azurerm_firewall" "example" {
  name                = "example-fw"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  threat_intel_mode   = "Deny"   # actively block known-malicious traffic

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.example.id
    public_ip_address_id = azurerm_public_ip.example.id
  }
}
```

## Remediation steps
1. Set `threat_intel_mode = "Deny"` on the `azurerm_firewall` resource (or `properties.threatIntelMode: "Deny"` in ARM/Bicep).
2. Before flipping to `Deny` in a production environment, review existing threat-intel `Alert` logs for false positives so legitimate traffic isn't unexpectedly blocked.
3. Note that if the firewall is instead managed via an `azurerm_firewall_policy` (Firewall Policy model), threat intelligence mode should be configured on the policy resource (`threat_intelligence_mode`) rather than directly on the firewall — see the newer Firewall Policy-based configuration if you've migrated off classic rule collections.
4. Monitor Azure Firewall diagnostic logs after the change to confirm blocked connections align with expected malicious sources and not legitimate business traffic.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureFirewallDenyThreatIntelMode.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureFirewallDenyThreatIntelMode.py
- Azure docs: https://learn.microsoft.com/en-us/azure/firewall/threat-intel
