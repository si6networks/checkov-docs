# CKV_AZURE_130: Ensure that PostgreSQL server enables infrastructure encryption
## Severity
**LOW** (score: 2.0/10)

Infrastructure (double) encryption adds a second layer of encryption beneath Azure's default at-rest encryption, so its absence is a defense-in-depth gap rather than leaving data unencrypted.

## Summary
This check verifies that an Azure Database for PostgreSQL server has infrastructure-level (double) encryption enabled, adding a second, independent layer of encryption at rest beneath Azure's standard service-level encryption.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **IaC frameworks:** Terraform, ARM templates, Bicep
- **Resource types:**
  - Terraform: `azurerm_postgresql_server`
  - ARM: `Microsoft.DBforPostgreSQL/servers`

## Why it matters
Azure Database for PostgreSQL encrypts data at rest by default using service-managed keys (a single layer of AES-256 encryption). Infrastructure (double) encryption adds a second layer of encryption at the storage/infrastructure level using a different encryption algorithm and key, so that a theoretical compromise or implementation flaw in one encryption layer does not by itself expose the underlying data — the second, independent layer still protects it. This is specifically relevant for organizations with regulatory or contractual requirements mandating "defense in depth" for data-at-rest protection (e.g. certain government, financial, or healthcare workloads that explicitly require double encryption), where a single point of cryptographic failure is considered an unacceptable risk for sensitive data.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects a single attribute:
- Terraform: `infrastructure_encryption_enabled`.
- ARM: `properties.infrastructureEncryption`.
- **PASS** if the Terraform attribute is truthy, or the ARM property equals the literal string `"Enabled"`.
- **FAIL** if the attribute/property is absent, `false` (Terraform), or any other value (ARM, e.g. `"Disabled"`).

## Non-compliant example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "psql-example"
  location             = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladminun"
  administrator_login_password = var.admin_password
  sku_name                     = "GP_Gen5_2"
  version                      = "11"

  ssl_enforcement_enabled = true
  # infrastructure_encryption_enabled not set -> single-layer encryption only
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "psql-example"
  location             = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladminun"
  administrator_login_password = var.admin_password
  sku_name                     = "GP_Gen5_2"
  version                      = "11"

  ssl_enforcement_enabled            = true
  infrastructure_encryption_enabled = true  # adds a second, independent encryption layer
}
```

## Remediation steps
1. Set `infrastructure_encryption_enabled = true` on the `azurerm_postgresql_server` resource (Terraform), or `properties.infrastructureEncryption: "Enabled"` (ARM/Bicep).
2. This setting can only be configured at server creation time — it cannot be toggled on an existing server, so for existing servers you must provision a new server with the setting enabled and migrate data across (e.g. via `pg_dump`/`pg_restore`, Azure Database Migration Service, or read replica promotion).
3. Be aware infrastructure/double encryption introduces additional I/O overhead, which may have a measurable performance impact — validate against your workload's latency requirements before broad rollout.
4. Confirm whether your compliance framework actually requires double encryption before adopting it universally, since it adds operational and performance cost without necessarily being required for all workloads.
5. Azure Database for PostgreSQL single-server is being retired in favor of the Flexible Server offering — check whether infrastructure encryption is available/required in your target deployment model going forward.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLEncryptionEnabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/PostgreSQLEncryptionEnabled.py)
- [Azure Database for PostgreSQL data encryption documentation](https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-data-encryption-postgresql)
