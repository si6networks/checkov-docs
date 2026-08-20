# CKV2_AZURE_16: Ensure that MySQL server enables customer-managed key for encryption

## Severity
**LOW** (score: 2.0/10)

Azure Database for MySQL is encrypted at rest by default with service-managed keys; lacking a customer-managed key reduces control over key rotation and revocation rather than exposing data in cleartext.

## Summary
This check ensures an Azure Database for MySQL (single) server has transparent data encryption configured with a customer-managed key backed by Azure Key Vault, rather than only Microsoft-managed keys.

## Applicability
- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `azurerm_mysql_server`, connected via `azurerm_mysql_server_key`, which in turn must be connected to an `azurerm_key_vault_key`.

## Why it matters
Databases frequently hold an organization's most sensitive data — customer records, financial data, credentials. Encryption at rest with a Microsoft-managed key provides baseline confidentiality but no independent key control: the organization cannot revoke database decryption capability on its own timeline (e.g. during incident response, offboarding a compromised environment, or fulfilling contractual/regulatory demands for customer-controlled encryption keys). A customer-managed key stored in Key Vault gives the data owner the ability to instantly disable access by disabling or deleting the key, enforce their own rotation policy, and produce audit evidence of exclusive key custody — controls many compliance frameworks (PCI-DSS, HIPAA, FedRAMP) require for data classified as highly sensitive.

## How Checkov evaluates this
Graph check (`MSQLenablesCustomerManagedKey.json`). PASS requires **all** of:
1. Filter to `azurerm_mysql_server` resources.
2. The MySQL server must have a **connection** to an `azurerm_mysql_server_key` resource.
3. That `azurerm_mysql_server_key` resource must in turn have a **connection** to an `azurerm_key_vault_key` resource.

FAIL if either link in that chain (server → server key → Key Vault key) is missing.

## Non-compliant example
```hcl
resource "azurerm_mysql_server" "mysql" {
  name                = "app-mysql-server"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  administrator_login          = "mysqladmin"
  administrator_login_password = var.mysql_admin_password

  sku_name   = "GP_Gen5_2"
  storage_mb = 51200
  version    = "5.7"
  ssl_enforcement_enabled = true
}
# No azurerm_mysql_server_key -> fails
```

## Remediated example
```hcl
resource "azurerm_mysql_server" "mysql" {
  name                = "app-mysql-server"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  administrator_login          = "mysqladmin"
  administrator_login_password = var.mysql_admin_password

  sku_name   = "GP_Gen5_2"
  storage_mb = 51200
  version    = "5.7"
  ssl_enforcement_enabled = true

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_key_vault_key" "mysql_key" {
  name         = "mysql-cmk"
  key_vault_id = azurerm_key_vault.kv.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}

resource "azurerm_mysql_server_key" "mysql_cmk" {
  server_id       = azurerm_mysql_server.mysql.id
  key_vault_key_id = azurerm_key_vault_key.mysql_key.id
}
```

## Remediation steps
1. Enable a `SystemAssigned` managed identity on the MySQL server (required for it to authenticate to Key Vault).
2. Grant the server's identity `Get`, `WrapKey`, and `UnwrapKey` permissions on the target Key Vault key.
3. Add an `azurerm_mysql_server_key` resource linking the server to the `azurerm_key_vault_key`.
4. Note: Azure Database for MySQL single server (the classic `azurerm_mysql_server`) is being retired in favor of Flexible Server — verify whether your MySQL deployment should migrate, since CMK configuration and this specific check target only the legacy single-server resource type.
5. Enabling CMK on an existing server is generally supported without downtime, but validate against current provider/service behavior in a test environment first.
6. Enable Key Vault soft-delete and purge protection (required), and set up monitoring/alerting for key expiration to avoid a database outage from an inaccessible encryption key.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/MSQLenablesCustomerManagedKey.json)
- [Azure: Data encryption for Azure Database for MySQL with customer-managed keys](https://learn.microsoft.com/en-us/azure/mysql/single-server/concepts-data-access-security-customer-managed-key)
