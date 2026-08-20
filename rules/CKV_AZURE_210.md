# CKV_AZURE_210: Ensure Azure Cognitive Search service allowed IPS does not give public Access

## Severity
**CRITICAL** (score: 8.5/10)

Allowing 0.0.0.0/0 in the Cognitive Search firewall opens the service to unauthenticated network-level access from the entire internet, exposing it to global scanning and credential/API-key attacks against a service that commonly indexes sensitive business data.

## Summary
This check ensures the `allowed_ips` firewall rule list on an Azure Cognitive Search service does not include the global CIDR range `0.0.0.0/0`, which would effectively make the service open to the entire internet.

## Applicability
- **Framework:** Terraform
- **Resource type:** `azurerm_search_service`

## Why it matters
Cognitive Search's IP firewall (`allowed_ips`) is meant to restrict management/data-plane access to a defined set of known client networks. Including `0.0.0.0/0` in that list defeats the purpose of the firewall entirely — it permits any host on the internet to attempt requests against the search service, exposing it to internet-wide scanning, credential-stuffing/brute-force attempts against API keys, and any application-layer vulnerabilities in the search API or its indexers to a global unauthenticated (network-level) audience. Because search services frequently index sensitive business content (CRM data, internal documents, customer records), an overly permissive network boundary substantially increases the risk that a subsequent authentication weakness or leaked API key becomes immediately, globally exploitable rather than confined to trusted networks.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` (a "must not equal" style check):
- **Inspected key:** `allowed_ips`
- **Forbidden values:** `["0.0.0.0/0"]`
- The check FAILS if `allowed_ips` contains the literal string `"0.0.0.0/0"` anywhere in the list.
- The check PASSES if `allowed_ips` is absent, empty, or contains only more specific, narrower CIDR ranges/IP addresses.

## Non-compliant example
```hcl
resource "azurerm_search_service" "example" {
  name                = "example-search"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"

  allowed_ips = ["0.0.0.0/0"]   # opens service to the entire internet
}
```

## Remediated example
```hcl
resource "azurerm_search_service" "example" {
  name                = "example-search"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"

  allowed_ips = ["203.0.113.0/24"]   # scoped to known corporate egress range
}
```

## Remediation steps
1. Remove any `0.0.0.0/0` entry from `allowed_ips`.
2. Replace it with the specific CIDR ranges of the networks that legitimately need to reach the service (corporate VPN egress IPs, specific application subnets, etc.).
3. For a more robust posture than IP allowlisting, consider using Azure Private Endpoint for the search service and disabling public network access entirely, removing exposure to the public internet altogether rather than relying on IP-based filtering (which can be spoofed or bypassed if a trusted network is itself compromised).
4. Audit any existing indexers/consumers to confirm their source IPs are covered by the new, narrower rule set before removing the open rule, to avoid breaking production access.
5. Re-apply — updating `allowed_ips` is a non-disruptive, in-place change.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureSearchAllowedIPsNotGlobal.py)
- [Azure Cognitive Search IP firewall documentation](https://learn.microsoft.com/en-us/azure/search/service-configure-firewall)
