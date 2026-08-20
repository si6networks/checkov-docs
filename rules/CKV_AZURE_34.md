# CKV_AZURE_34: Ensure that 'Public access level' is set to Private for blob containers

## Severity
**CRITICAL** (score: 9.3/10)

A blob container with public (Container or Blob) access lets anyone on the internet read or enumerate its contents without any credentials, one of the most common and damaging real-world causes of cloud data breaches.

## Summary
This check ensures Azure Storage blob containers do not allow anonymous public read access to blobs or container listings.

## Applicability
- **Frameworks:** Terraform, ARM, Bicep (via shared entities)
- **Resource types:** `Microsoft.Storage/storageAccounts/blobServices/containers`, `containers`, `blobServices/containers`, `azurerm_storage_container`

## Why it matters
A blob container with public access level set to `Container` (list + read any blob without authentication) or `Blob` (read any blob if you know its URL, but no listing) allows anyone on the internet to retrieve — or, worse, enumerate and retrieve — the container's contents with no credentials at all. This is one of the most common and damaging cloud misconfigurations in the wild: numerous public data breaches have originated from exactly this setting being left enabled on containers holding backups, exported databases, user uploads, or internal documents. Setting access to `Private` requires every read to be authenticated (account key, Azure AD, or a deliberately-issued SAS token with a defined expiry and scope), putting access control back under your management rather than "public by URL."

## How Checkov evaluates this
**ARM check**: reads `properties.publicAccess`. **FAIL** if its value (case-insensitive) is `"container"` or `"blob"`. **PASS** if it is absent (the default is private/`None`) or any other value.

**Terraform check** (`BaseResourceValueCheck` with `missing_block_result=PASSED`): inspects `container_access_type` on `azurerm_storage_container`, expecting `"private"`. **PASS** if set to `"private"` or if the attribute is omitted entirely (provider default is private). **FAIL** if set to `"blob"` or `"container"`.

## Non-compliant example
```hcl
resource "azurerm_storage_container" "example" {
  name                  = "example-container"
  storage_account_name  = azurerm_storage_account.example.name
  container_access_type = "container"   # anonymous list + read
}
```

## Remediated example
```hcl
resource "azurerm_storage_container" "example" {
  name                  = "example-container"
  storage_account_name  = azurerm_storage_account.example.name
  container_access_type = "private"   # was "container"
}
```

## Remediation steps
1. Set `container_access_type = "private"` on every `azurerm_storage_container` (or simply omit the attribute, since private is the default).
2. In ARM/Bicep templates, remove `properties.publicAccess` or explicitly set it to `"None"`.
3. If the container's contents genuinely need to be shared externally, use time-limited SAS tokens or Azure CDN/Front Door with authenticated origin access instead of enabling blanket public access.
4. Additionally verify the parent storage account's `allow_blob_public_access` (a.k.a. "Allow Blob public access" account-level toggle) is disabled — this provides a second, account-wide guardrail even if an individual container is later misconfigured.
5. Audit existing containers for public access level regularly, since this setting is a frequent target of automated internet-wide scanners looking for exposed data.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageBlobServiceContainerPrivateAccess.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/StorageBlobServiceContainerPrivateAccess.py)
- [Azure Storage: prevent anonymous public read access](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent)
