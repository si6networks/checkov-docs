# CKV2_AZURE_41: Ensure storage account is configured with SAS expiration policy

## Severity
**LOW** (score: 2.0/10)

Without a SAS expiration policy, shared-access-signature tokens generated against the storage account can remain valid indefinitely, giving an overly permissive, hard-to-revoke access path if a token leaks.

## Summary
This check ensures that if an Azure Storage Account still allows Shared Key authorization (and thus Shared Access Signature generation), it must also enforce a SAS expiration policy so that generated SAS tokens cannot be issued with unlimited or excessively long lifetimes.

## Applicability
- **IaC framework:** Terraform (graph-based check)
- **Resource type:** `azurerm_storage_account`

## Why it matters
SAS tokens grant time-scoped access to storage resources without requiring Azure AD authentication, but if no expiration policy is enforced at the account level, an administrator (or a compromised credential/script) could generate a SAS token with an extremely long or effectively unlimited validity period. A long-lived SAS token that leaks (e.g., committed to a public repo, logged, or shared insecurely) becomes a standing, hard-to-revoke access credential — unlike Azure AD tokens, SAS tokens can't be centrally revoked except by rotating the underlying account key (which breaks every other SAS derived from it) or by using stored access policies. Enforcing a maximum SAS expiration period at the account level bounds the blast radius of any leaked token.

## How Checkov evaluates this
Graph-based JSON policy over `azurerm_storage_account`. PASSES when either:
1. `shared_access_key_enabled` equals `"false"` (Shared Key/SAS generation is disabled entirely, so the policy is moot), **or**
2. `shared_access_key_enabled` exists and equals `"true"`, **and** a `sas_policy` block exists, **and** `sas_policy.expiration_period` has length greater than `"0"` (i.e., a non-empty expiration period string like `"7.00:00:00"` is configured).

FAILS when Shared Key auth is enabled (or the attribute is left at its default `true`) but no `sas_policy` block with a populated `expiration_period` is defined.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  shared_access_key_enabled = true
  # no sas_policy block -> SAS tokens can be issued with unbounded expiration
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

  shared_access_key_enabled = true

  sas_policy {
    expiration_period = "7.00:00:00"   # max 7 days validity for any generated SAS token
    expiration_action  = "Log"
  }
}
```
Alternatively, disable Shared Key auth entirely (see CKV2_AZURE_40) to eliminate SAS-based access altogether.

## Remediation steps
1. If Shared Key authorization is required for legacy compatibility, add a `sas_policy` block to the `azurerm_storage_account` resource with a bounded `expiration_period` (format `DD.HH:MM:SS`).
2. Prefer the strongest option: disable `shared_access_key_enabled` and move consumers to Azure AD-based access, which removes the SAS attack surface entirely (see CKV2_AZURE_40).
3. If SAS tokens must be issued, favor user-delegation SAS (backed by Azure AD credentials, individually revocable) over account-key SAS.
4. Set `expiration_action` appropriately (`Log` to just warn, or enforce blocking depending on your compliance posture) and monitor for policy violations.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureStorageAccConfig_SAS_expirePolicy.json)
- [Azure Storage: SAS expiration policy documentation](https://learn.microsoft.com/en-us/azure/storage/common/sas-expiration-policy)
