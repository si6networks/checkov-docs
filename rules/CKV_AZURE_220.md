# CKV_AZURE_220: Ensure Firewall policy has IDPS mode as deny
## Severity
**HIGH** (score: 7.5/10)

An IDPS mode set to Alert rather than Deny means the firewall policy only logs detected intrusion attempts instead of blocking them, leaving known attack patterns free to reach internal resources.

## Summary
Ensures that an Azure Firewall Policy's Intrusion Detection and Prevention System (IDPS) is configured in `Deny` mode, so traffic matching known attack signatures is actively blocked rather than only alerted on.

## Applicability
- **Terraform**: `azurerm_firewall_policy` — inspects `intrusion_detection[0].mode`

## Why it matters
Azure Firewall Premium's IDPS feature inspects traffic for signatures matching known exploit patterns, malware communication, and other attack traffic using a Microsoft-maintained signature database. IDPS supports three modes: `Off`, `Alert` (log matches but allow traffic through), and `Deny` (log and actively block matching traffic). Leaving IDPS in `Alert` mode (or off) means the firewall correctly identifies malicious traffic patterns but takes no preventive action — an attacker's exploit attempt, malware beaconing, or known scanning tool traffic is allowed to reach its destination while only being recorded in logs that may not be reviewed in real time. This converts what should be an active, real-time prevention control into a passive detection control, significantly delaying incident response and allowing attacks that match known signatures to succeed even though the firewall correctly detected them. `Deny` mode closes this gap by having the firewall itself terminate the connection at the moment a signature match occurs.

## How Checkov evaluates this
The check inspects `intrusion_detection/[0]/mode` on `azurerm_firewall_policy`. The expected value is the literal string `"Deny"`. The check **PASSES** only if `mode` equals `"Deny"`; it **FAILS** if the mode is `"Alert"`, `"Off"`, or the `intrusion_detection` block/attribute is absent.

## Non-compliant example
```hcl
resource "azurerm_firewall_policy" "example" {
  name                = "example-fw-policy"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Premium"

  intrusion_detection {
    mode = "Alert"   # detects but does not block
  }
}
```

## Remediated example
```hcl
resource "azurerm_firewall_policy" "example" {
  name                = "example-fw-policy"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Premium"

  intrusion_detection {
    mode = "Deny"   # actively blocks traffic matching attack signatures
  }
}
```

## Remediation steps
1. Set `intrusion_detection.mode = "Deny"` on the `azurerm_firewall_policy` resource.
2. Note that IDPS is a Firewall Premium tier feature — the associated `azurerm_firewall`/`azurerm_firewall_policy` `sku` must be `"Premium"`, which carries additional cost versus Standard.
3. Before switching from `Alert` to `Deny` in production, review historical IDPS alert logs for false positives; use `intrusion_detection.signature_overrides` to tune or bypass specific signature IDs that generate noise for known-legitimate traffic before enforcing blocking.
4. Roll out `Deny` mode gradually (e.g., non-production first, or scoped via `traffic_bypass` rules for trusted internal ranges) to avoid unexpected outages from blocked legitimate traffic.
5. Monitor Firewall diagnostic logs post-change to confirm blocked traffic aligns with genuine threats.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureFirewallPolicyIDPSDeny.py
- Azure docs: https://learn.microsoft.com/en-us/azure/firewall/premium-features#idps
