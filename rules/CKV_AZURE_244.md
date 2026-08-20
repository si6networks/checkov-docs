# CKV_AZURE_244: Avoid the use of local users for Azure Storage unless necessary

## Severity
**LOW** (score: 2.0/10)

Enabling local (SFTP/username-password) users on Azure Storage bypasses Azure AD-based access control, allowing authentication via standalone credentials that are easier to leak, guess, or leave unrotated on a sensitive data store.

## Summary
This check ensures Azure Storage accounts do not have local user (SFTP-style) authentication enabled unless it is genuinely needed, favoring Azure AD/RBAC-based access instead.

## Applicability
- **Terraform**: `azurerm_storage_account` resources — inspects `local_user_enabled`, with conditional logic also referencing `is_hns_enabled`.

## Why it matters
Azure Storage "local users" are an authentication mechanism (used primarily to support SFTP access) that authenticates with storage-account-scoped credentials (password or SSH key) independent of Azure AD. These credentials live outside of Azure AD's centralized identity, conditional access, and audit-logging pipeline — meaning access via local users doesn't benefit from Azure AD sign-in monitoring, Conditional Access policies (MFA, location/device restrictions), or centralized credential lifecycle management. A local user credential leaked from a script, config file, or compromised SFTP client provides direct authenticated access to the storage account's data with none of the identity-governance visibility that Azure AD-based access (via RBAC + managed identity/service principal) provides. Since SFTP support (which is what requires local users) is only needed for specific interoperability scenarios, this check flags accounts that have enabled it without an apparent SFTP use case (see evaluation logic below), pushing teams toward Azure AD-based access wherever it's not strictly required.

## How Checkov evaluates this
`BaseResourceValueCheck` on `azurerm_storage_account` with custom `scan_resource_conf` logic (inspecting `local_user_enabled`, expected value `false`):
1. If `local_user_enabled` is explicitly set (to any value, per the code's `is not None or local_user_enabled` condition — effectively: if the key is present at all), the check falls through to the standard value check, which PASSES only if `local_user_enabled == false` and FAILS if `true`.
2. If `local_user_enabled` is not set, the check instead looks at `is_hns_enabled` (Hierarchical Namespace / Data Lake Gen2). If HNS is not enabled (or unset), the check PASSES — since SFTP (which needs local users) requires HNS, an account without HNS has no legitimate use for local users being on, so it's assumed fine by default.
3. If HNS *is* enabled but `local_user_enabled` wasn't explicitly set, the check falls through to the standard value check against the (implicit) default, which effectively FAILS since local users aren't explicitly disabled — this is the scenario the check is really targeting: HNS-enabled (Data Lake Gen2 / SFTP-capable) storage accounts that haven't explicitly turned local users off.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  is_hns_enabled           = true   # Data Lake Gen2 / SFTP-capable
  # local_user_enabled not set -> HNS is on, local users implicitly available, FAILS
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
  is_hns_enabled           = true
  local_user_enabled       = false   # <-- explicitly disabled, PASSES
}
```

## Remediation steps
1. If your storage account does not need SFTP or other local-user-based access, set `local_user_enabled = false` explicitly.
2. If SFTP access genuinely is required (a common legitimate use case for HNS-enabled accounts), you may need to accept/suppress this finding rather than disable local users — but scope the local user's permissions as tightly as possible (specific container/path permissions) and rotate its credentials regularly.
3. Prefer Azure AD-based access (RBAC roles like `Storage Blob Data Contributor` assigned to a managed identity or service principal) over local users wherever the consuming application/tool supports it.
4. Where SFTP is required, ensure `sftp_enabled` is combined with strong, individually-scoped local user credentials (SSH key-based auth preferred over password) and that access is monitored via storage account diagnostic logs.
5. Document and periodically review any storage accounts where this check is intentionally suppressed, since local users represent an identity path outside normal Azure AD governance.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageLocalUsers.py
- Azure docs: https://learn.microsoft.com/en-us/azure/storage/blobs/secure-file-transfer-protocol-support
