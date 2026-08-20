# CKV2_AZURE_27: Ensure Azure AD authentication is enabled for Azure SQL (MSSQL)
## Severity
**LOW** (score: 2.0/10)

Without Azure AD authentication, SQL Server relies solely on SQL login/password auth, which lacks centralized identity controls like MFA and conditional access, increasing risk of credential-based compromise of the database.

## Summary
This check verifies that an Azure SQL logical server has Azure Active Directory administration configured, rather than relying solely on SQL (username/password) authentication.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **IaC frameworks:** ARM templates, Bicep (compiles to ARM), and Terraform (two separate check implementations)
- **Resource/entity types involved:** `Microsoft.Sql/servers` (ARM/Bicep), `azurerm_mssql_server` (Terraform)

## Why it matters
SQL authentication (a static administrator username and password) is inherently weaker than Azure AD authentication: it cannot participate in centralized identity governance, has no native support for MFA, cannot be centrally revoked when an employee leaves, and the shared admin password is a prime target for credential leakage in code, CI logs, or configuration files. Azure AD authentication centralizes identity, supports conditional access policies, MFA enforcement, and immediate deprovisioning through the directory — closing off an entire class of stolen-credential attacks against the database's administrative surface. Relying purely on SQL auth for the server admin account means a single leaked password grants full administrative control over every database on the server.

## How Checkov evaluates this
Two different implementations exist depending on IaC type:

**ARM/Bicep** (`SQLServerUsesADAuth.py`) — a negative-value attribute check:
- It inspects the `properties/administratorLogin` field on `Microsoft.Sql/servers`.
- The forbidden value is `ANY_VALUE` (a Checkov sentinel meaning "any value present at all triggers failure").
- In other words: **if `administratorLogin` is set to any value, the check FAILS.** The check's author's own code comment notes the intent is really "ensure *only* AD auth is used (not user/pass)" — i.e., it flags servers that still have a SQL admin login configured at all, since Azure SQL servers can be created without a SQL login when only AAD-only authentication is used.

**Terraform** (`AzureConfigMSSQLwithAD.json`) — a graph-based attribute check with the opposite framing:
- The `azuread_administrator` block must `exist` on the `azurerm_mssql_server` resource.
- The `azuread_administrator.login_username` attribute must have a non-zero word count (i.e., it must actually be populated with a name, not empty).
- Both conditions must hold for the resource to PASS — meaning a Terraform-defined SQL server FAILS if it has no `azuread_administrator` block or an empty `login_username`.

Note the divergence: the ARM check fails on *presence* of a SQL login, whereas the Terraform check fails on *absence* of an AD administrator block. Practically, secure configurations satisfy both: configure `azuread_administrator`/AAD admin and avoid relying on the SQL admin login for ongoing access.

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = "example-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password

  # No azuread_administrator block configured.
}
```

## Remediated example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = "example-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password

  # Added: Azure AD administrator for the server.
  azuread_administrator {
    login_username              = "sql-admins-group"
    object_id                   = data.azuread_group.sql_admins.object_id
    azuread_authentication_only = true
  }
}
```

## Remediation steps
1. Add an `azuread_administrator` block to the `azurerm_mssql_server` (Terraform) or the equivalent `administrators` property under `Microsoft.Sql/servers` (ARM/Bicep), pointing to an AAD group or user that will administer the server.
2. Set `login_username` to a non-empty value (ideally an AAD group name for break-glass/administrative access, not an individual).
3. Where feasible, set `azuread_authentication_only = true` to fully disable SQL authentication for the server admin path, eliminating the static password attack surface entirely.
4. If migrating an existing server, coordinate with application teams first — connection strings using SQL auth will stop working once `azuread_authentication_only` is enabled; migrate application connections to AAD tokens/managed identities before cutting over.
5. Requires an AAD group/user to already exist (referenced via a `data "azuread_group"` or similar) before applying.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SQLServerUsesADAuth.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureConfigMSSQLwithAD.json)
- [Azure AD authentication for Azure SQL](https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-overview)
