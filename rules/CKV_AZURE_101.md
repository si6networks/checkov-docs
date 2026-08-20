# CKV_AZURE_101: Ensure that Azure Cosmos DB disables public network access
## Severity
**HIGH** (score: 7.5/10)

Leaving Cosmos DB reachable over the public network broadens the attack surface for a data store that commonly holds sensitive application data, relying solely on account keys/RBAC as the remaining barrier.

## Summary
This check ensures that an Azure Cosmos DB account's public network access setting is disabled, so the account can only be reached through private endpoints/VNet integration rather than over the public internet.

## Applicability
- **Terraform**: `azurerm_cosmosdb_account` (inspects `public_network_access_enabled`)
- **ARM/Bicep**: `Microsoft.DocumentDB/databaseAccounts` (inspects `properties/publicNetworkAccess`)

## Why it matters
Cosmos DB is frequently used to store application state, user data, or session information, and by default its data-plane endpoint is reachable from the public internet (subject to IP firewall rules and auth). Leaving public network access enabled — even with authentication and IP allow-lists in place — expands the attack surface: the endpoint is discoverable and can be targeted by credential-stuffing, key-leak exploitation, or DDoS, and misconfigured or overly-broad IP rules become a much more severe exposure than they would be on a private-only endpoint. Disabling public network access and requiring traffic to flow only through Private Link/VNet service endpoints ensures that even a leaked account key or vnet-rule mistake cannot be exploited from an arbitrary internet host — an attacker would first need a foothold inside the private network.

## How Checkov evaluates this
- **Terraform**: inspects `public_network_access_enabled` on `azurerm_cosmosdb_account`. The check expects this to be `false`; if it is `true` (or the attribute defaults to `true`, which is the provider default), the check **FAILS**.
- **ARM**: inspects `properties/publicNetworkAccess` and expects the string `"Disabled"`. Any other value (including the default `"Enabled"`) **FAILS**.

## Non-compliant example
```hcl
resource "azurerm_cosmosdb_account" "bad_example" {
  name                = "bad-cosmosdb"
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

  public_network_access_enabled = true
}
```

## Remediated example
```hcl
resource "azurerm_cosmosdb_account" "good_example" {
  name                = "good-cosmosdb"
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

  # Fix: disable public network access; reachable only via private endpoint / vnet rules
  public_network_access_enabled = false

  is_virtual_network_filter_enabled = true

  virtual_network_rule {
    id = azurerm_subnet.example.id
  }
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess = "Disabled"` (ARM/Bicep) on the Cosmos DB account.
2. Provision a Private Endpoint (`azurerm_private_endpoint` with a `private_service_connection` targeting `Microsoft.DocumentDB/databaseAccounts`) so authorized clients inside the VNet can still reach the account.
3. If some clients cannot yet move to Private Link, use `is_virtual_network_filter_enabled` plus `virtual_network_rule` blocks to scope access to specific subnets as an interim step — but note this is weaker than disabling public access entirely.
4. Update application connection strings/DNS to resolve through the private endpoint's private DNS zone.
5. Test connectivity from all legitimate client networks before disabling public access in production, since this is a breaking change for anything connecting over the public endpoint.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/CosmosDBDisablesPublicNetwork.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBDisablesPublicNetwork.py)
- [Azure docs: Configure private endpoints for Azure Cosmos DB](https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-private-endpoints)
