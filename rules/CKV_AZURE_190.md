# CKV_AZURE_190: Ensure that Storage blobs restrict public access

## Severity
**CRITICAL** (score: 9.0/10)

Allowing nested items (containers/blobs) in a storage account to be set public risks direct anonymous internet access to potentially sensitive blob data, a common and severe cause of real-world data breaches.

## Summary
This check ensures an Azure Storage account has anonymous/public access to blob containers disabled at the account level, so individual containers cannot be made publicly readable.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (`azurerm` provider)
- **Resource type:** `azurerm_storage_account`

## Why it matters
Azure Storage allows individual blob containers to be configured for anonymous public read access (either full container listing or blob-only access), but this capability is gated by an account-level switch, `allow_nested_items_to_be_public`. When this is left enabled (the historical default), any container-level access-policy change — whether intentional or an operator mistake — can instantly expose blob data to the entire internet with no authentication. This is one of the most common real-world cloud data-breach patterns: a developer sets a container to "public" for convenience during testing, or a misconfigured IaC template flips a container's access level, and sensitive data (backups, logs, customer files, credentials) becomes world-readable, often undetected for a long time. Disabling this account-level setting removes the possibility entirely — no container under that account can be made public regardless of its own configuration, closing off this class of accidental exposure at the root.

## How Checkov evaluates this
The check inspects the `allow_nested_items_to_be_public` attribute of `azurerm_storage_account`. It expects the value `false`. If the attribute is `true`, or omitted (Azure's historical default for this setting is `true`), the check FAILS. Only an explicit `false` PASSES.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # allow_nested_items_to_be_public defaults to true
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "example" {
  name                             = "examplestorageacct"
  resource_group_name              = azurerm_resource_group.example.name
  location                         = azurerm_resource_group.example.location
  account_tier                     = "Standard"
  account_replication_type         = "LRS"
  allow_nested_items_to_be_public  = false
}
```

## Remediation steps
1. Set `allow_nested_items_to_be_public = false` on every `azurerm_storage_account` resource.
2. Audit existing containers for any that currently rely on public/anonymous access (`public_access` set to `blob` or `container` on `azurerm_storage_container`) — these will stop being publicly reachable once the account-level setting is disabled, so identify and migrate any legitimate use cases (e.g. static website assets, public downloads) to alternatives like SAS tokens, Azure CDN with origin access restricted to the storage account, or a dedicated public-access storage account explicitly carved out and reviewed for that purpose.
3. Prefer scoped, time-limited SAS tokens or Azure AD-authenticated access for anything that previously relied on anonymous container access.
4. This is an in-place setting change with no resource replacement, but coordinate with application owners before flipping it on a production account, since it can break public content delivery immediately if containers were relying on it.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageBlobRestrictPublicAccess.py
- [Azure Storage "Prevent anonymous access" documentation](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent)
