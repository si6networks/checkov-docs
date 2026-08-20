# CKV_AZURE_96: Ensure that MySQL server enables infrastructure encryption
## Severity
**LOW** (score: 2.0/10)

MySQL data is already encrypted at rest by default in Azure, so missing infrastructure (double) encryption is a defense-in-depth gap rather than leaving the data unencrypted.

## Summary
This check verifies that an Azure Database for MySQL server has infrastructure-level (double) encryption enabled, adding a second layer of encryption underneath the standard service-level encryption.

## Applicability
- **Terraform**: `azurerm_mysql_server` (inspects `infrastructure_encryption_enabled`)
- **ARM templates**: `Microsoft.DBforMySQL/flexibleServers` (inspects `properties.dataencryption`)
- **Bicep**: resources compiling to the above ARM type

## Why it matters
Azure encrypts data at rest for MySQL by default using a service-level encryption layer. Infrastructure (double) encryption adds a **second, independent encryption layer at the infrastructure/hardware level**, using a different encryption algorithm and key than the service-level encryption. This matters because:
- It provides defense-in-depth: if a vulnerability or implementation flaw is ever found in one encryption layer or its specific algorithm, the data remains protected by the second, independently-implemented layer.
- Certain regulatory and compliance frameworks (e.g. FIPS 140-2 validated environments, government/defense workloads, some financial-sector requirements) mandate double encryption of data at rest.
- It closes a theoretical gap where a single point of cryptographic failure (bug, key compromise, weak configuration) could otherwise expose data protected by only one layer.

The tradeoff is a modest performance overhead, which is why it's opt-in rather than default, but it's recommended for the most security/compliance-sensitive workloads.

## How Checkov evaluates this
- **Terraform**: `BaseResourceValueCheck` inspects `infrastructure_encryption_enabled` with no explicit expected value override, meaning it expects a truthy value; if it's `false` or absent (defaults to `false`), the check FAILS.
- **ARM**: Inspects `properties.dataencryption`. PASSES if `dataencryption` is present and is a dict (i.e., encryption configuration block exists); FAILS if it's absent or falsy; returns `UNKNOWN` if the value is an unparsed string or if `properties` itself is missing/malformed.

## Non-compliant example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example-mysqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mysqladmin"
  administrator_login_password = var.mysql_admin_password
  sku_name                      = "GP_Gen5_2"
  storage_mb                    = 51200
  version                        = "5.7"
  ssl_enforcement_enabled        = true

  infrastructure_encryption_enabled = false   # <-- single-layer encryption only
}
```

## Remediated example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example-mysqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mysqladmin"
  administrator_login_password = var.mysql_admin_password
  sku_name                      = "GP_Gen5_2"
  storage_mb                    = 51200
  version                        = "5.7"
  ssl_enforcement_enabled        = true

  infrastructure_encryption_enabled = true   # <-- adds a second, independent encryption layer
}
```

## Remediation steps
1. Set `infrastructure_encryption_enabled = true` (Terraform) or configure the equivalent `properties.dataencryption` block (ARM/Bicep).
2. This setting can only be configured at **server creation time** in Azure Database for MySQL (single server) — it cannot be toggled on an existing server, so this typically requires provisioning a new server and migrating data.
3. Weigh the modest additional latency/CPU overhead of double encryption against your compliance requirements; enable it selectively for workloads that genuinely require it rather than blanket-enabling for all servers.
4. Note: Azure Database for MySQL single server is being retired/deprecated in favor of Flexible Server — evaluate whether migrating to `azurerm_mysql_flexible_server` (which has its own encryption configuration model) is a better long-term path than remediating this specific resource type.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLEncryptionEnabled.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/MySQLEncryptionEnabled.py
