# CKV_AZURE_140: Ensure that Local Authentication is disabled on CosmosDB
## Severity
**LOW** (score: 2.0/10)

Leaving local (key-based) authentication enabled on CosmosDB preserves a static-secret access path that bypasses Azure AD identity controls (conditional access, MFA, audit trail), so a leaked key grants full data-plane access.

## Summary
This check ensures a Cosmos DB account of kind `GlobalDocumentDB` (the SQL/Core API) has local authentication (primary/secondary account keys) disabled, requiring Azure AD-based authentication instead.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **ARM**: `Microsoft.DocumentDB/databaseAccounts` resources, property `properties/disableLocalAuth` — only evaluated when `kind` is `GlobalDocumentDB`.
- **Terraform**: `azurerm_cosmosdb_account` resource, attribute `local_authentication_disabled` — only evaluated when `kind` is `GlobalDocumentDB`.
- **Bicep**: compiles to the same ARM resource type.

## Why it matters
Cosmos DB's local authentication mode relies on long-lived primary/secondary account keys — static, symmetric secrets that grant full read/write access to the account's data. These keys don't support Azure AD's identity guarantees: no per-identity audit trail, no MFA, no conditional access, no fine-grained RBAC scoping, and no automatic expiration tied to an identity lifecycle (e.g. an offboarded employee). If a key leaks — via a committed config file, a compromised CI secret, or an exposed connection string — an attacker gets full data-plane access to the database that is valid until manually rotated. Disabling local auth forces all data-plane access through Azure AD tokens, enabling role-based access control (Cosmos DB built-in data reader/contributor roles), auditable per-principal access, and integration with conditional access/MFA policies, substantially reducing the blast radius of any single leaked secret.

## How Checkov evaluates this
Both variants first gate on the resource's `kind`: the check only applies (and evaluates) when `conf.get("kind")` is `GlobalDocumentDB` (ARM) or `["GlobalDocumentDB"]` (Terraform) — for other kinds (e.g. MongoDB, Cassandra API accounts) the result is `UNKNOWN` (not applicable/not evaluated), since local auth disablement is a SQL-API-specific setting. When the kind matches, it delegates to the base `BaseResourceValueCheck` logic inspecting `properties/disableLocalAuth` (ARM) or `local_authentication_disabled` (Terraform) and expects the value `True` to PASS. Absent or `false` FAILS.

## Non-compliant example
```hcl
resource "azurerm_cosmosdb_account" "example" {
  name                = "example-cosmosdb"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = "eastus"
    failover_priority = 0
  }
  # local_authentication_disabled left at default (false) -- FAILS
}
```

## Remediated example
```hcl
resource "azurerm_cosmosdb_account" "example" {
  name                = "example-cosmosdb"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  local_authentication_disabled = true  # forces Azure AD-based authentication only

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = "eastus"
    failover_priority = 0
  }
}
```

## Remediation steps
1. Set `local_authentication_disabled = true` (Terraform) or `properties.disableLocalAuth: true` (ARM/Bicep) — applies only to SQL (Core) API accounts (`kind = "GlobalDocumentDB"`).
2. Before disabling, migrate all application connection strings/SDK configuration from key-based auth to Azure AD token-based auth (e.g. `DefaultAzureCredential` in the Cosmos SDK) and assign appropriate Cosmos DB data-plane RBAC roles (`Cosmos DB Built-in Data Reader`/`Contributor`) to the relevant managed identities/service principals.
3. Test thoroughly in a non-production environment first — disabling local auth is a breaking change for any client still using account keys or connection strings, and there is no automatic fallback.
4. Rotate/regenerate existing account keys after cutover as a precaution, even though they'll no longer be usable, to fully invalidate any previously leaked copies.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/CosmosDBLocalAuthDisabled.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBLocalAuthDisabled.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-setup-rbac
