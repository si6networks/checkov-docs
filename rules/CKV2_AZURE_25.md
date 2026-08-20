# CKV2_AZURE_25: Ensure Azure SQL database Transparent Data Encryption (TDE) is enabled
## Severity
**LOW** (score: 2.0/10)

Disabling Transparent Data Encryption leaves database files, backups, and logs unencrypted at rest, exposing potentially sensitive data if storage media or backups are compromised.

## Summary
This check verifies that an Azure SQL Database (`azurerm_mssql_database`) does not have Transparent Data Encryption explicitly disabled.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based attribute check)
- **Resource type involved:** `azurerm_mssql_database`

## Why it matters
Transparent Data Encryption encrypts the database's data and log files at rest, protecting against a class of attacks where an adversary gains access to the raw physical storage, backup files, or exported `.bak`/`.mdf` files without going through SQL authentication — for example, a stolen backup, a compromised storage account holding database exports, or physical disk access in a compromised host. Without TDE, sensitive data at rest is stored in plaintext on disk, meaning many compliance frameworks (PCI-DSS, HIPAA, SOC 2) would consider the control gap a reportable finding, and any exposure of the underlying storage media directly exposes customer data.

## How Checkov evaluates this
This is a **graph-based attribute check** using a negative match with a whitelist-style default:
- The `transparent_data_encryption_enabled` attribute must **not equal** `"false"`.

This means the check PASSES both when the attribute is explicitly set to `true` and when it is **omitted entirely** (since Azure SQL Database has TDE enabled by default and the omitted value is not literally `"false"`). It only FAILS when someone has explicitly set `transparent_data_encryption_enabled = false`, deliberately turning off a secure-by-default setting.

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = "example-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}

resource "azurerm_mssql_database" "example" {
  name      = "example-db"
  server_id = azurerm_mssql_server.example.id
  sku_name  = "S0"

  # Explicitly disabling TDE — data at rest is stored unencrypted.
  transparent_data_encryption_enabled = false
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
}

resource "azurerm_mssql_database" "example" {
  name      = "example-db"
  server_id = azurerm_mssql_server.example.id
  sku_name  = "S0"

  # Fixed: leave TDE enabled (or omit the attribute to use the secure default).
  transparent_data_encryption_enabled = true
}
```

## Remediation steps
1. Remove any explicit `transparent_data_encryption_enabled = false` setting from `azurerm_mssql_database` resources, or set it to `true`.
2. If TDE was previously disabled on a live database, re-enabling it triggers an encryption scan of the database — this is an online operation in Azure SQL but can take time proportional to database size; monitor via `sys.dm_database_encryption_keys`.
3. For stronger key control, consider pairing TDE with a customer-managed key via `azurerm_mssql_server_transparent_data_encryption` and Key Vault integration instead of relying solely on the service-managed key.
4. Verify no application or compliance tooling depends on TDE being disabled (rare, but some legacy performance-sensitive workloads historically disabled it — re-evaluate that tradeoff given modern TDE has minimal overhead).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureSqlDbEnableTransparentDataEncryption.json)
- [Transparent data encryption for SQL Database](https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview)
