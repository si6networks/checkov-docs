# CKV_AZURE_124: Ensure that Azure Cognitive Search disables public network access
## Severity
**HIGH** (score: 7.5/10)

Public network access to a search service exposes indexed data and query/administration endpoints to the internet, risking unauthorized data exposure or brute-force access attempts against the service.

## Summary
This check verifies that an Azure Cognitive Search (Azure AI Search) service has public network access disabled, so the search service is only reachable through private connectivity (e.g. Private Endpoint) rather than over the public internet.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_search_service`

## Why it matters
Azure Cognitive Search services frequently index sensitive data — customer records, documents, internal knowledge bases — and expose that data via a queryable REST API. When public network access is left enabled, the search endpoint (and its query/admin API keys, if leaked or brute-forced) is reachable from any internet address, turning a single leaked API key into a direct path to bulk data exfiltration via search queries. Disabling public network access forces all access through private networking (Private Link/Private Endpoint), so even a leaked API key is far less useful to an external attacker because network-level access to the service is also required — a critical defense-in-depth layer for any search index containing PII, credentials, or proprietary content.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `public_network_access_enabled` attribute:
- **PASS** if `public_network_access_enabled = false`.
- **FAIL** if the attribute is `true` or omitted (Azure's provider default for this attribute is `true`, i.e., public access enabled, so an omitted attribute fails).

## Non-compliant example
```hcl
resource "azurerm_search_service" "example" {
  name                = "search-example"
  resource_group_name = azurerm_resource_group.example.name
  location             = "eastus"
  sku                  = "standard"
  # public_network_access_enabled not set -> defaults to true (publicly reachable)
}
```

## Remediated example
```hcl
resource "azurerm_search_service" "example" {
  name                = "search-example"
  resource_group_name = azurerm_resource_group.example.name
  location             = "eastus"
  sku                  = "standard"

  public_network_access_enabled = false  # only reachable via Private Endpoint
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` on the `azurerm_search_service` resource.
2. Provision an `azurerm_private_endpoint` connecting to the search service's `Microsoft.Search/searchServices` sub-resource, and integrate it with a Private DNS zone (`privatelink.search.windows.net`) so clients resolve to the private IP.
3. Update any application configuration/firewall rules that assumed public reachability, and ensure app services/functions that query the index are deployed in (or peered with) the VNet hosting the private endpoint, or use VNet integration.
4. This is a mutable property in most cases (no resource replacement needed), but test in a non-production search service first since it will immediately cut off any clients relying on the public endpoint.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureSearchPublicNetworkAccessDisabled.py)
- [Azure Cognitive Search private endpoints documentation](https://learn.microsoft.com/en-us/azure/search/service-create-private-endpoint)
