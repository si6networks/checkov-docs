# CKV2_AZURE_7: Ensure that Azure Active Directory Admin is configured

## Severity
**LOW** (score: 2.0/10)

Without an Azure AD admin configured, the SQL server relies solely on local SQL authentication, forgoing centralized identity governance, MFA and conditional access enforcement, which weakens access control but does not itself grant access.

## Summary
This check verifies that every Azure SQL Server has an Azure Active Directory (Azure AD) administrator configured, rather than relying solely on SQL authentication.

## Applicability
- **Terraform**: `azurerm_sql_server` (must be connected to an `azurerm_sql_active_directory_administrator` resource)

This is a graph-based connection check.

## Why it matters
SQL authentication (username/password stored directly in the database engine) has weaker security controls than Azure AD authentication: no native support for MFA, no centralized credential lifecycle management, no integration with conditional access policies, and passwords that can be shared, hardcoded, or leaked without any centralized detection. Configuring an Azure AD administrator allows organizations to manage database access through the same identity provider used for the rest of the environment — enabling MFA enforcement, centralized deprovisioning when an employee leaves, audit logging tied to real identities, and Conditional Access policies (e.g., blocking access from unmanaged devices or untrusted locations). Without an AD admin, database administration is stuck on a legacy, weaker authentication model.

## How Checkov evaluates this
Implemented as a JSON graph query.

- FAIL: an `azurerm_sql_server` resource exists with no connected `azurerm_sql_active_directory_administrator` resource.
- PASS: the SQL server has a connected `azurerm_sql_active_directory_administrator` resource (the check only requires the association to exist; it does not further validate which identity is set as admin).

## Non-compliant example
```hcl
resource "azurerm_sql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}
# No azurerm_sql_active_directory_administrator resource -> FAILS
```

## Remediated example
```hcl
resource "azurerm_sql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}

# Added: Azure AD administrator for the SQL server
resource "azurerm_sql_active_directory_administrator" "example" {
  server_name         = azurerm_sql_server.example.name
  resource_group_name = azurerm_resource_group.example.name
  login               = "sqladmins@example.onmicrosoft.com"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azuread_group.sql_admins.object_id
}
```

## Remediation steps
1. Add an `azurerm_sql_active_directory_administrator` resource for each `azurerm_sql_server`, referencing an Azure AD group (preferred, for easier membership management) or user as the admin.
2. Obtain the `tenant_id` and `object_id` via the `azurerm_client_config` and `azuread_group`/`azuread_user` data sources rather than hardcoding IDs.
3. Where possible, disable or restrict SQL authentication login for administrative accounts once AD auth is confirmed working, and require Azure AD authentication for application connections too.
4. If using the newer `azurerm_mssql_server` resource, use the equivalent `azurerm_mssql_server_extended_auditing_policy`/`azuread_administrator` block — Checkov has a separate, analogous check for that resource type.
5. Note: enabling Azure AD admin requires the Terraform service principal/user to have sufficient Azure AD directory permissions to read the referenced group/user.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureActiveDirectoryAdminIsConfigured.json)
- [Azure AD authentication for Azure SQL documentation](https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-overview)
