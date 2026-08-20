# CKV2_AZURE_17: Ensure that PostgreSQL server enables customer-managed key for encryption

## Severity
**LOW** (score: 2.0/10)

Azure Database for PostgreSQL is encrypted at rest by default with service-managed keys; missing a customer-managed key limits key rotation/revocation control rather than leaving data unencrypted.

## Summary
This check ensures an Azure Database for PostgreSQL (single) server has transparent data encryption configured with a customer-managed key backed by Azure Key Vault, rather than only Microsoft-managed keys.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `azurerm_postgresql_server`, connected via `azurerm_postgresql_server_key`, which in turn must be connected to an `azurerm_key_vault_key`.

## Why it matters
PostgreSQL databases commonly hold core application state and sensitive records. Relying only on Microsoft-managed encryption keys means the organization has no independent mechanism to revoke decryption capability, no control over rotation timing, and cannot produce evidence of exclusive key custody demanded by many compliance regimes (PCI-DSS, HIPAA, FedRAMP, and various data-sovereignty regulations). A customer-managed key in Key Vault lets the data owner instantly cut off access to the database's encrypted data by disabling the key — an important lever during incident response, contract termination, or a suspected credential compromise — that simply isn't available with platform-managed-only encryption.

## How Checkov evaluates this
Graph check (`PGSQLenablesCustomerManagedKey.json`). PASS requires **all** of:
1. Filter to `azurerm_postgresql_server_key` resources (note: unlike the MySQL variant, this check's filter targets the `azurerm_postgresql_server_key` resource type directly, not the server itself — meaning the check evaluates when a `azurerm_postgresql_server_key` resource is defined).
2. An `azurerm_postgresql_server` must have a **connection** to that `azurerm_postgresql_server_key`.
3. That `azurerm_postgresql_server_key` must have a **connection** to an `azurerm_key_vault_key`.

FAIL if any link in that chain (server → server key → Key Vault key) is missing, or if no `azurerm_postgresql_server_key` resource exists for the server at all.

## Non-compliant example
```hcl
resource "azurerm_postgresql_server" "pg" {
  name                = "app-pg-server"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  administrator_login          = "pgadmin"
  administrator_login_password = var.pg_admin_password

  sku_name   = "GP_Gen5_2"
  storage_mb = 51200
  version    = "11"
  ssl_enforcement_enabled = true
}
# No azurerm_postgresql_server_key -> fails
```

## Remediated example
```hcl
resource "azurerm_postgresql_server" "pg" {
  name                = "app-pg-server"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  administrator_login          = "pgadmin"
  administrator_login_password = var.pg_admin_password

  sku_name   = "GP_Gen5_2"
  storage_mb = 51200
  version    = "11"
  ssl_enforcement_enabled = true

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_key_vault_key" "pg_key" {
  name         = "pg-cmk"
  key_vault_id = azurerm_key_vault.kv.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}

resource "azurerm_postgresql_server_key" "pg_cmk" {
  server_id       = azurerm_postgresql_server.pg.id
  key_vault_key_id = azurerm_key_vault_key.pg_key.id
}
```

## Remediation steps
1. Enable a `SystemAssigned` managed identity on the PostgreSQL server.
2. Grant that identity `Get`, `WrapKey`, and `UnwrapKey` permissions on the target Key Vault key.
3. Add an `azurerm_postgresql_server_key` resource linking the server and the `azurerm_key_vault_key`.
4. Note: Azure Database for PostgreSQL single server is deprecated in favor of Flexible Server — assess whether this workload should be migrated, since this check and CMK support here target only the legacy single-server resource type.
5. Test CMK enablement in a non-production environment first; while typically an in-place operation, validate current provider behavior to rule out any unexpected downtime.
6. Ensure Key Vault soft-delete and purge protection are enabled (required), and monitor key expiration/rotation to prevent a database outage from a revoked or expired key.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/PGSQLenablesCustomerManagedKey.json)
- [Azure: Data encryption for Azure Database for PostgreSQL with customer-managed keys](https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-data-access-and-security-customer-managed-key)
