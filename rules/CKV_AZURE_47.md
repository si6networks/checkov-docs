# CKV_AZURE_47: Ensure 'Enforce SSL connection' is set to 'ENABLED' for MariaDB servers

## Severity
**HIGH** (score: 7.5/10)

Disabling SSL enforcement on MariaDB servers allows database traffic, including authentication and query data, to travel unencrypted and be intercepted or tampered with in transit.

## Summary
This check verifies that an Azure Database for MariaDB server requires SSL/TLS for all client connections, rejecting unencrypted database connections.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_mariadb_server`
- **ARM templates**: `Microsoft.DBforMariaDB/servers`
- **Bicep**: `Microsoft.DBforMariaDB/servers`

## Why it matters
Database connections carry highly sensitive data in transit — query results, authentication credentials, and often the raw contents of rows including PII, financial records, or secrets stored in application tables. If SSL enforcement is disabled, a MariaDB server will accept unencrypted TCP connections, meaning any attacker positioned on the network path (a compromised VNet peer, a misconfigured NSG allowing broader-than-intended access, or an on-path attacker in a shared/multi-tenant network) can passively sniff full query traffic and captured credentials, or actively tamper with data in transit via a MITM attack. Because database connections are often long-lived and carry bulk data (unlike a single web request), the exposure from unencrypted DB traffic is typically much larger in volume than a single leaked API call.

## How Checkov evaluates this
Implemented as a generic value check on both platforms:
- **ARM**: Inspects `properties.sslEnforcement`. PASSES only if the value equals `"Enabled"`.
- **Terraform**: Inspects `ssl_enforcement_enabled`. PASSES only if it is truthy (`true`).

## Non-compliant example
```hcl
resource "azurerm_mariadb_server" "example" {
  name                = "example-mariadb"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadmin"
  administrator_login_password = var.admin_password

  sku_name   = "B_Gen5_2"
  version    = "10.2"
  storage_mb = 5120

  ssl_enforcement_enabled = false
}
```

## Remediated example
```hcl
resource "azurerm_mariadb_server" "example" {
  name                = "example-mariadb"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadmin"
  administrator_login_password = var.admin_password

  sku_name   = "B_Gen5_2"
  version    = "10.2"
  storage_mb = 5120

  ssl_enforcement_enabled = true
}
```

## Remediation steps
1. Set `ssl_enforcement_enabled = true` on the `azurerm_mariadb_server` resource, or `properties.sslEnforcement = "Enabled"` in ARM/Bicep.
2. Update client applications and connection strings to require SSL (e.g., append `sslmode=require` or the MariaDB-connector equivalent, and ensure client trust stores include the Azure database SSL CA certificate).
3. Consider also setting `minimum_tls_version` (a related property) to enforce TLS 1.2, since SSL enforcement alone doesn't dictate protocol version.
4. Test all existing application connections against a staging instance with SSL enforced before applying to production — legacy clients or drivers without SSL support will fail to connect after this change.
5. Note: Azure Database for MariaDB is on a Microsoft-announced retirement path (in favor of Azure Database for MySQL/PostgreSQL Flexible Server) — factor migration planning into any long-term remediation strategy.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/MariaDBSSLEnforcementEnabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MariaDBSSLEnforcementEnabled.py)
- [Azure Database for MariaDB SSL connectivity documentation](https://learn.microsoft.com/en-us/azure/mariadb/concepts-ssl-connection-security)
