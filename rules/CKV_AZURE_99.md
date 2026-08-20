# CKV_AZURE_99: Ensure Cosmos DB accounts have restricted access
## Severity
**HIGH** (score: 7.5/10)

A Cosmos DB account without virtual network filtering or IP restrictions is reachable from any network, exposing a multi-region database service that often holds sensitive application data to unauthorized access attempts.

## Summary
This check verifies that an Azure Cosmos DB account either has public network access disabled, or — if public access is enabled and multi-region writes are on — has network restrictions (a VNet filter or IP range filter) configured so it isn't openly reachable from any address.

## Applicability
- **Terraform**: `azurerm_cosmosdb_account` (inspects `public_network_access_enabled`, `is_virtual_network_filter_enabled`, `virtual_network_rule`, `ip_range_filter`)
- **ARM templates**: `Microsoft.DocumentDB/databaseAccounts` (inspects `properties.enableMultipleWriteLocations`, `properties.isVirtualNetworkFilterEnabled`, `properties.virtualNetworkRules`, `properties.ipRules`)
- **Bicep**: resources compiling to `Microsoft.DocumentDB/databaseAccounts`

## Why it matters
Cosmos DB accounts commonly store application data, user records, and other sensitive information behind primary/secondary access keys or Azure AD auth. If an account is left reachable from any network without additional restriction:
- An attacker who obtains a leaked connection string or access key (a disturbingly common occurrence via source-code leaks, misconfigured CI secrets, or client-side exposure) can query the database directly from anywhere on the internet, with no network-layer barrier to stop them.
- There's no defense-in-depth: keys are the *only* control, so key compromise equals full data compromise, rather than requiring both a leaked key *and* network-level access.
- Compliance frameworks that require data stores to be reachable only from trusted network segments (VNets, specific IP allow-lists) cannot be satisfied.

Restricting access via VNet service endpoints/private access or an explicit IP allow-list ensures that even a leaked key alone is insufficient for an attacker to reach the database — they'd also need network-level access to a trusted segment.

## How Checkov evaluates this
The logic mirrors the same "restricted access" pattern across both IaC types:
- If `public_network_access_enabled` (Terraform) / `enableMultipleWriteLocations` presence checks — more precisely, if the account is reachable via public network (attribute absent or `true`), the check inspects whether network restriction is configured:
  - If `is_virtual_network_filter_enabled` (Terraform) / `isVirtualNetworkFilterEnabled` (ARM) is truthy **and** either a `virtual_network_rule`/`virtualNetworkRules` list is non-empty, **or** an `ip_range_filter`/`ipRules` is non-empty — the check PASSES (network-level restriction is in place).
  - Otherwise, it FAILS.
- If public network access is not enabled at all (attribute explicitly disabled), the check PASSES outright, since there is no unrestricted public path to worry about.

In short: public accessibility alone is not automatically a fail, but public accessibility **without** a VNet filter or IP range restriction is a fail.

## Non-compliant example
```hcl
resource "azurerm_cosmosdb_account" "example" {
  name                = "example-cosmosdb"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.example.location
    failover_priority = 0
  }

  # public_network_access_enabled defaults to true
  # is_virtual_network_filter_enabled not set
  # no ip_range_filter, no virtual_network_rule -> wide open
}
```

## Remediated example
```hcl
resource "azurerm_cosmosdb_account" "example" {
  name                = "example-cosmosdb"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.example.location
    failover_priority = 0
  }

  is_virtual_network_filter_enabled = true   # <-- enforce network restriction

  virtual_network_rule {
    id = azurerm_subnet.example.id           # <-- only this subnet may reach it
  }

  ip_range_filter = ["203.0.113.0/24"]       # <-- or an explicit allow-listed range
}
```

## Remediation steps
1. Prefer disabling public network access entirely (`public_network_access_enabled = false`) and using Private Endpoints for all connectivity where feasible — this is the most restrictive and recommended posture.
2. If public access must remain enabled (e.g. for client scenarios that require it), set `is_virtual_network_filter_enabled = true` and add at least one `virtual_network_rule` (VNet service endpoint) or `ip_range_filter` entry.
3. Enumerate and allow-list only the specific subnets/IP ranges that genuinely need access — avoid overly broad CIDR ranges.
4. Re-verify application connectivity after applying restrictions, since previously-working connections from unlisted networks will be blocked.
5. Combine with Azure AD-based data-plane RBAC (instead of key-based auth) where possible, for defense in depth beyond network restriction alone.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBAccountsRestrictedAccess.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/CosmosDBAccountsRestrictedAccess.py
