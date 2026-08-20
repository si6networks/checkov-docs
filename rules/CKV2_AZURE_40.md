# CKV2_AZURE_40: Ensure storage account is not configured with Shared Key authorization

## Severity
**LOW** (score: 2.0/10)

Leaving Shared Key authorization enabled on a storage account permits access via long-lived, non-revocable account keys that bypass Azure AD RBAC, conditional access, and MFA entirely if leaked.

## Summary
This check ensures an Azure Storage Account has Shared Key (account-key based) authorization disabled, forcing all data-plane access to use Azure AD (Entra ID) identity-based authorization instead.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check)
- **Resource type:** `azurerm_storage_account`

## Why it matters
Shared Key authorization allows anyone holding the storage account's access key (or a SAS token derived from it) to authenticate as the storage account itself, with no per-identity accountability, no conditional access, and no ability to revoke a single compromised credential without rotating the key for every consumer. These keys are long-lived, high-privilege secrets that are frequently over-shared, hardcoded in application config, or leaked (e.g., in source control, CI logs, or container images). If an attacker obtains the account key, they get full data-plane access to the account, indistinguishable from legitimate traffic, and Azure AD-based conditional access, MFA, and PIM controls provide no protection since key-based access bypasses Azure AD entirely. Disabling Shared Key auth forces all clients (including Azure services and SDKs) to authenticate with Azure AD identities, enabling fine-grained RBAC, auditable sign-ins, and instant revocation via identity controls.

## How Checkov evaluates this
Graph-based JSON policy over `azurerm_storage_account`. PASSES only when both conditions hold:
1. `shared_access_key_enabled` attribute exists.
2. It equals `"false"` (case-insensitive).

If the attribute is absent (Azure/provider default is `true`, i.e., Shared Key enabled) or explicitly set to `true`, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # shared_access_key_enabled not set -> defaults to true (Shared Key auth allowed)
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  shared_access_key_enabled = false   # forces Azure AD authorization for all data-plane access
}
```

## Remediation steps
1. Set `shared_access_key_enabled = false` on the `azurerm_storage_account` resource.
2. Migrate all consuming applications/SDKs to authenticate via Azure AD (Managed Identity, service principal, or user identity) instead of connection strings/account keys.
3. Assign appropriate Azure RBAC roles (`Storage Blob Data Contributor`, `Storage Blob Data Reader`, etc.) to the identities that need access.
4. Note: any existing SAS tokens generated from the account key will stop working immediately; user-delegation SAS (Azure AD-backed) should be used instead if delegated, time-limited access is still needed.
5. Test thoroughly before rollout — legacy tools, some Azure services, and certain SDK versions may not support Azure AD authentication for storage and could break.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureStorageAccConfigSharedKeyAuth.json)
- [Azure Storage: Prevent Shared Key authorization documentation](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent)
