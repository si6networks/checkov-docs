# CKV_AZURE_181: Ensure that data explorer/Kusto uses managed identities to access Azure resources securely

## Severity
**MEDIUM** (score: 5.0/10)

Without a managed identity, the cluster must rely on statically stored credentials or connection strings to reach other Azure resources, increasing the risk of credential leakage and making least-privilege access harder to enforce.

## Summary
This check ensures an Azure Data Explorer (Kusto) cluster has a managed identity configured, rather than relying on static credentials to access other Azure resources.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (`azurerm` provider)
- **Resource type:** `azurerm_kusto_cluster`

## Why it matters
Kusto clusters frequently need to reach other Azure resources — Storage accounts for external tables, Key Vault for secrets, Event Hubs for ingestion, etc. Without a managed identity, these integrations typically require long-lived credentials (connection strings, SAS tokens, or service principal secrets) to be stored in configuration, application settings, or Key Vault access policies referencing a static principal. Such secrets can be leaked via source control, logs, or misconfigured access policies, and they must be manually rotated. A system-assigned or user-assigned managed identity lets Azure AD issue short-lived tokens automatically, eliminating the need to provision, store, or rotate credentials, and it allows fine-grained RBAC scoping to exactly the resources the cluster needs.

## How Checkov evaluates this
The check inspects the `identity[0].type` attribute of the `azurerm_kusto_cluster` resource. Any non-empty value (`SystemAssigned`, `UserAssigned`, or `SystemAssigned, UserAssigned`) satisfies the check (`ANY_VALUE` is accepted) — it PASSES as long as an `identity` block with a `type` is present. If the `identity` block is absent, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_kusto_cluster" "example" {
  name                = "kustocluster"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku {
    name     = "Standard_D11_v2"
    capacity = 2
  }
  # no identity block defined
}
```

## Remediated example
```hcl
resource "azurerm_kusto_cluster" "example" {
  name                = "kustocluster"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku {
    name     = "Standard_D11_v2"
    capacity = 2
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Add an `identity` block to the `azurerm_kusto_cluster` resource, setting `type` to `SystemAssigned` (simplest), `UserAssigned`, or both.
2. If using `UserAssigned`, also set `identity_ids` to reference the `azurerm_user_assigned_identity` resource(s).
3. Grant the resulting managed identity the minimum required RBAC roles on the target resources (e.g. `Storage Blob Data Reader` on a storage account) instead of reusing broad credentials.
4. Update any data connections/external tables that currently use connection strings or SAS tokens to instead use the managed identity where the Kusto data connection type supports it.
5. Deploying this change to an existing cluster is generally non-disruptive (no resource replacement required), but downstream RBAC assignments must be created before removing old credentials to avoid breaking ingestion/query paths.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataExplorerServiceIdentity.py
- [Azure Data Explorer managed identities documentation](https://learn.microsoft.com/en-us/azure/data-explorer/configure-managed-identities-cluster)
