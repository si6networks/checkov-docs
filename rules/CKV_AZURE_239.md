# CKV_AZURE_239: Ensure Azure Synapse Workspace administrator login password is not exposed

## Severity
**MEDIUM** (score: 5.0/10)

Storing the SQL administrator login password directly in the Synapse Workspace resource definition hardcodes a privileged database credential in source/state, where it can be read by anyone with repository or plan access.

## Summary
This check ensures the SQL administrator login password for an Azure Synapse Analytics workspace is never set as a plaintext/inline value in the IaC configuration itself.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_synapse_workspace` resources — flags presence of the `sql_administrator_login_password` attribute.
- **ARM/Bicep**: `Microsoft.Synapse/workspaces` — flags presence of `properties.sqlAdministratorLoginPassword`.

## Why it matters
Any secret value written directly into a Terraform `.tf` file or ARM/Bicep template becomes part of the source-controlled configuration: it can be seen by anyone with repo read access, gets captured in Terraform plan/apply output and state files, may be logged by CI/CD pipelines, and persists in git history even after later removal/rotation. A Synapse workspace's SQL administrator password grants full administrative control over the workspace's SQL pools — an attacker who obtains it (via a leaked repo, a misconfigured CI log, or an exposed Terraform state file) gets direct database-level access to potentially sensitive analytical data, and password-only auth for this account also lacks the auditability and conditional-access benefits of Azure AD authentication.

This check exists purely to catch the pattern of putting the password inline in code at all, regardless of how "strong" the string looks, because the failure mode is exposure through the configuration/version-control pipeline rather than password strength.

## How Checkov evaluates this
Both are `BaseResourceCheck`s doing simple key-presence detection:
- **Terraform**: FAILS if `'sql_administrator_login_password'` is present anywhere in the resource config at all (regardless of value); PASSES only if the key is entirely absent.
- **ARM**: FAILS if `conf["properties"]["sqlAdministratorLoginPassword"]` is truthy; PASSES if absent or empty.

## Non-compliant example
```hcl
resource "azurerm_synapse_workspace" "example" {
  name                                 = "example-synapse"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = "P@ssw0rd1234!"   # inline plaintext secret -> FAILS

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediated example
```hcl
resource "azurerm_synapse_workspace" "example" {
  name                                 = "example-synapse"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "sqladminuser"
  # sql_administrator_login_password omitted entirely -> PASSES
  # Managed via Azure AD-only auth, or password rotated out-of-band via Key Vault + azapi/az cli.

  identity {
    type = "SystemAssigned"
  }

  aad_admin {
    login     = "synapse-admins@example.com"
    object_id = data.azuread_group.synapse_admins.object_id
    tenant_id = data.azurerm_client_config.current.tenant_id
  }
}
```

## Remediation steps
1. Remove `sql_administrator_login_password` (Terraform) or `properties.sqlAdministratorLoginPassword` (ARM/Bicep) from the resource definition entirely — do not merely reference a variable that still gets baked into plan/state in plaintext form without proper handling.
2. Prefer Azure AD-only authentication for the Synapse workspace (configure an `aad_admin` block) so a SQL password is not the primary access path at all.
3. If a SQL admin password is still required for a legacy tool, generate/rotate it out-of-band (e.g., via `az synapse workspace` CLI or a one-time secure pipeline step) and store it in Azure Key Vault rather than in source-controlled IaC; do not read it back into Terraform state unless using `sensitive = true` variables and a secured backend.
4. Audit Terraform state files and CI logs for any historical exposure of this value if it was previously set inline, and rotate the password if so.
5. Restrict access to the state backend (e.g., Azure Storage account with RBAC + encryption) regardless, since sensitive Terraform variables still end up in state.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SynapseWorkspaceAdministratorLoginPasswordHidden.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SynapseWorkspaceAdministratorLoginPasswordHidden.py
- Azure docs: https://learn.microsoft.com/en-us/azure/synapse-analytics/sql/active-directory-authentication
