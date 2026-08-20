# CKV_AZURE_28: Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server

## Severity
**HIGH** (score: 7.5/10)

Without enforced SSL, a MySQL server accepts unencrypted connections, exposing credentials and query/result data in transit to anyone able to intercept the network path.

## Summary
This check ensures Azure Database for MySQL (single server) enforces SSL/TLS on all client connections rather than permitting plaintext connections.

## Applicability
- **Frameworks:** Terraform, ARM, Bicep (via shared entities)
- **Resource types:** `Microsoft.DBforMySQL/servers`, `azurerm_mysql_server`

## Why it matters
Without enforced SSL, a MySQL client can connect to the database server over an unencrypted channel. Any network position between the application and the database — a compromised router, a misconfigured VPN, a shared/public network segment, or an attacker who has gained a foothold on the VNet — can passively sniff or actively intercept credentials, query text, and result sets (including sensitive rows) in cleartext. Enforcing SSL ensures every connection is encrypted in transit, closing off this network-level eavesdropping and man-in-the-middle vector, which is especially important since database traffic frequently carries authentication secrets and unmasked sensitive data.

## How Checkov evaluates this
**ARM check** (`BaseResourceValueCheck`): inspects `properties/sslEnforcement` and requires it equal `"Enabled"`.

**Terraform check** (`BaseResourceValueCheck`): inspects `ssl_enforcement_enabled` on `azurerm_mysql_server` and requires it be truthy (the check's default expected value for a boolean attribute is `true`).

- **PASS**: SSL enforcement attribute is explicitly enabled.
- **FAIL**: attribute missing, disabled, or set to any other value.

## Non-compliant example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example-mysqlserver"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "B_Gen5_2"
  version  = "5.7"

  administrator_login          = "mysqladminun"
  administrator_login_password = var.admin_password

  ssl_enforcement_enabled = false
}
```

## Remediated example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example-mysqlserver"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "B_Gen5_2"
  version  = "5.7"

  administrator_login          = "mysqladminun"
  administrator_login_password = var.admin_password

  ssl_enforcement_enabled = true   # was false
}
```

## Remediation steps
1. Set `ssl_enforcement_enabled = true` (Terraform) or `properties.sslEnforcement = "Enabled"` (ARM/Bicep) on the MySQL server resource.
2. Ensure application connection strings/drivers are configured to negotiate TLS (e.g., `sslmode=require` or driver-equivalent), or connections will start failing once enforcement is turned on.
3. Note: `azurerm_mysql_server` (single server) is a deprecated/retiring SKU family — for new deployments prefer `azurerm_mysql_flexible_server`, which enforces TLS by default and has its own equivalent check.
4. Validate certificate trust chains (e.g., DigiCert Global Root G2) are present in client trust stores before enforcing SSL in production.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLServerSSLEnforcementEnabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/MySQLServerSSLEnforcementEnabled.py)
- [Azure Database for MySQL SSL connectivity](https://learn.microsoft.com/en-us/azure/mysql/single-server/concepts-ssl-connection-security)
