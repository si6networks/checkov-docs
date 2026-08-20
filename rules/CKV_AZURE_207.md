# CKV_AZURE_207: Ensure Azure Cognitive Search service uses managed identities to access Azure resources

## Severity
**MEDIUM** (score: 5.0/10)

Without a managed identity, Cognitive Search must use static credentials to reach data sources or Key Vault, increasing the surface for credential leakage even though it doesn't directly expose the search service itself.

## Summary
This check ensures an Azure Cognitive Search service has a system-assigned managed identity configured, so it can authenticate to other Azure resources (such as data sources or Key Vault) without stored credentials.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `azurerm_search_service`

## Why it matters
Cognitive Search often needs to connect to other Azure resources — pulling data from indexers connected to Azure SQL, Cosmos DB, or Blob Storage, or retrieving customer-managed encryption keys from Key Vault. Without a managed identity, these connections require static credentials (connection strings, account keys, or SAS tokens) to be stored somewhere the search service can read them — increasing the number of places a secret can leak (configuration files, indexer definitions, application settings) and creating long-lived credentials that must be manually rotated. A system-assigned managed identity lets Azure AD issue short-lived tokens automatically scoped to the search service's own identity, letting administrators grant fine-grained RBAC roles (e.g. read-only Storage Blob Data Reader) instead of full-account keys, and instantly revoke access by removing role assignments rather than hunting down and rotating a shared secret.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `identity/[0]/type`
- **Expected value:** `"SystemAssigned"` (note: implemented via `get_expected_values`, effectively requiring an exact match to `SystemAssigned`).
- The check FAILS if no `identity` block is defined, or if `identity.type` is anything other than `"SystemAssigned"` (e.g. absent, or a different identity type not matching this exact string).

## Non-compliant example
```hcl
resource "azurerm_search_service" "example" {
  name                = "example-search"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
  # no identity block - no managed identity configured
}
```

## Remediated example
```hcl
resource "azurerm_search_service" "example" {
  name                = "example-search"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"

  identity {
    type = "SystemAssigned"   # managed identity enabled
  }
}
```

## Remediation steps
1. Add an `identity` block with `type = "SystemAssigned"` to the `azurerm_search_service` resource.
2. Update any data source connections (indexers pointing at Storage, SQL, Cosmos DB) to use the managed identity for authentication instead of embedded connection strings, where the target service supports Azure AD auth.
3. Grant the search service's managed identity the minimum required RBAC role on each target resource (e.g. `Storage Blob Data Reader` for a Blob Storage indexer data source, or Key Vault access policy/RBAC for CMK scenarios).
4. Re-apply — this is a non-disruptive, in-place update.
5. If you need cross-resource sharing of the identity or don't want it tied to the search service's lifecycle, consider whether a user-assigned identity fits your architecture better, though note this specific check only accepts `SystemAssigned` as a passing value.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureSearchManagedIdentity.py)
- [Azure Cognitive Search managed identity documentation](https://learn.microsoft.com/en-us/azure/search/search-howto-managed-identities-data-sources)
