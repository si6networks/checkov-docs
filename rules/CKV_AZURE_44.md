# CKV_AZURE_44: Ensure Storage Account is using the latest version of TLS encryption

## Severity
**LOW** (score: 2.0/10)

Allowing TLS versions below 1.2 for storage account traffic permits use of deprecated, weak transport encryption, exposing data in transit to downgrade and interception attacks against a sensitive data store.

## Summary
This check verifies that an Azure Storage Account enforces a minimum TLS version of 1.2 (or 1.3 for Terraform) for all client connections, rejecting older, weaker TLS protocol versions.

## Applicability
- **Terraform**: `azurerm_storage_account`
- **ARM templates**: `Microsoft.Storage/storageAccounts`
- **Bicep**: `Microsoft.Storage/storageAccounts`

## Why it matters
Older TLS versions (1.0, 1.1) have known cryptographic weaknesses — vulnerable cipher suites, susceptibility to protocol downgrade and padding-oracle style attacks (e.g., BEAST, POODLE-adjacent issues), and lack of modern AEAD cipher support. Storage accounts serve data over HTTPS to a wide variety of clients, including third-party integrations and legacy systems; if the account accepts TLS 1.0/1.1, an on-path attacker in a position to intercept traffic (e.g., on a compromised network segment, public Wi-Fi client, or misconfigured proxy) has a larger attack surface to attempt to force a downgrade to a weaker cipher and potentially recover or tamper with data in transit — including SAS tokens, account keys, and the blob/queue/table data itself. Enforcing TLS 1.2+ is now a standard, low-cost control most regulatory and industry frameworks (PCI-DSS, NIST, CIS) mandate, since virtually all reasonably modern clients support it.

## How Checkov evaluates this
- **ARM**: Reads `properties.minimumTlsVersion`. PASSES only if the value is exactly `"TLS1_2"`. Any other value (or missing property) FAILS.
- **Terraform**: Reads `min_tls_version`. PASSES if it is `"TLS1_2"` or `"TLS1_3"`. Any other value (including the historical default `TLS1_0`) FAILS.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_0"
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
  min_tls_version          = "TLS1_2"
}
```

## Remediation steps
1. Set `min_tls_version = "TLS1_2"` (or `"TLS1_3"` where supported) on the `azurerm_storage_account` resource, or `properties.minimumTlsVersion = "TLS1_2"` in ARM/Bicep.
2. Before enforcing, audit any legacy clients, on-prem gateways, or older SDKs that might still negotiate TLS 1.0/1.1 — they will start failing connections once this is enforced.
3. This setting can typically be updated in place without resource replacement.
4. Combine with `enable_https_traffic_only = true` (a related but distinct setting — see CKV_AZURE_3 territory) to ensure plaintext HTTP is also rejected, not just weak TLS.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/StorageAccountMinimumTlsVersion.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountMinimumTlsVersion.py)
- [Azure Storage minimum TLS version documentation](https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version)
