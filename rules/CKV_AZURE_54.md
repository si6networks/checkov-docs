# CKV_AZURE_54: Ensure MySQL is using the latest version of TLS encryption
## Severity
**HIGH** (score: 7.0/10)

Allowing connections below TLS 1.2 exposes database traffic (often carrying credentials and sensitive query data) to downgrade attacks and weak cipher suites that undermine confidentiality and integrity of the channel.

## Summary
This check fails when an Azure Database for MySQL server does not enforce TLS 1.2 as its minimum TLS version, allowing clients to negotiate weaker, deprecated TLS protocol versions.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

Applies to Terraform (`azurerm_mysql_server`), ARM templates, and Bicep, for the resource type `Microsoft.DBforMySQL/servers`.

## Why it matters
Older TLS versions (TLS 1.0, TLS 1.1) have known cryptographic weaknesses — including vulnerability to protocol downgrade attacks (e.g. POODLE-style attacks), weak cipher suite support, and lack of modern AEAD ciphers — that can allow an on-path attacker to intercept, tamper with, or decrypt traffic between the application and the database. Since database traffic often carries credentials, PII, and other sensitive query/response data, permitting connections over outdated TLS undermines confidentiality and integrity guarantees even though the channel is nominally "encrypted." Enforcing TLS 1.2 as the floor closes off downgrade paths and ensures only currently-secure cipher suites and handshake mechanisms are used for the connection.

## How Checkov evaluates this
- ARM/Bicep: reads `properties/minimalTlsVersion` on `Microsoft.DBforMySQL/servers` and expects the exact string `"TLS1_2"`. Any other value (including `TLSEnforcementDisabled`, `TLS1_0`, `TLS1_1`, or the field being absent) FAILS.
- Terraform: reads the `ssl_minimal_tls_version_enforced` attribute on `azurerm_mysql_server` and expects `"TLS1_2"`. The Azure provider default for this attribute is `TLSEnforcementDisabled`, so omitting it FAILS the check.

## Non-compliant example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example-mysqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "B_Gen5_2"
  version  = "5.7"

  administrator_login          = "mysqladminun"
  administrator_login_password = var.mysql_password

  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_0"
}
```

## Remediated example
```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example-mysqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "B_Gen5_2"
  version  = "5.7"

  administrator_login          = "mysqladminun"
  administrator_login_password = var.mysql_password

  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"  # enforce modern TLS floor
}
```

## Remediation steps
1. Set `ssl_minimal_tls_version_enforced = "TLS1_2"` (Terraform) or `properties.minimalTlsVersion: "TLS1_2"` (ARM/Bicep).
2. Ensure `ssl_enforcement_enabled = true` is also set — TLS version enforcement is meaningless if SSL/TLS itself isn't required.
3. Verify all client drivers/application connection strings support and request TLS 1.2 (older MySQL client libraries or JDBC drivers may need updates).
4. This applies to the single-server SKU (`azurerm_mysql_server`, now deprecated); for `azurerm_mysql_flexible_server`, TLS is controlled differently via server parameters (`require_secure_transport`, `tls_version`).
5. Changing this setting can briefly interrupt connections for clients that are only capable of older TLS versions — test in a non-production environment first.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/MySQLServerMinTLSVersion.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLServerMinTLSVersion.py)
- [Azure docs: TLS enforcement in Azure Database for MySQL](https://learn.microsoft.com/en-us/azure/mysql/single-server/concepts-ssl-connection-security)
