# CKV_AZURE_29: Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server

## Severity
**HIGH** (score: 7.5/10)

Without enforced SSL, a PostgreSQL server accepts unencrypted connections, exposing credentials and query/result data in transit to network eavesdropping.

## Summary
This check ensures Azure Database for PostgreSQL (single server) enforces SSL/TLS on all client connections rather than permitting plaintext connections.

## Applicability
- **Frameworks:** Terraform, ARM, Bicep (via shared entities)
- **Resource types:** `Microsoft.DBforPostgreSQL/servers`, `azurerm_postgresql_server`

## Why it matters
Without enforced SSL, a PostgreSQL client can connect over an unencrypted TCP channel. Anyone with visibility into the network path — a compromised intermediate host, a misrouted VNet peering, or an attacker who has gained a foothold anywhere between the application tier and the database — can capture credentials, query text, and returned rows in cleartext. This is particularly dangerous for databases holding authentication secrets, PII, or financial data. Enforcing SSL guarantees every client connection is encrypted in transit, eliminating this network eavesdropping and MITM risk regardless of the underlying network's trust level.

## How Checkov evaluates this
**ARM check** (`BaseResourceValueCheck`): inspects `properties/sslEnforcement` and requires it equal `"Enabled"`.

**Terraform check** (`BaseResourceValueCheck`): inspects `ssl_enforcement_enabled` on `azurerm_postgresql_server` and requires it be truthy.

- **PASS**: SSL enforcement is explicitly enabled.
- **FAIL**: attribute missing, disabled, or set to any other value.

## Non-compliant example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "example-psqlserver"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "B_Gen5_2"
  version  = "11"

  administrator_login          = "psqladminun"
  administrator_login_password = var.admin_password

  ssl_enforcement_enabled = false
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "example-psqlserver"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  sku_name = "B_Gen5_2"
  version  = "11"

  administrator_login          = "psqladminun"
  administrator_login_password = var.admin_password

  ssl_enforcement_enabled = true   # was false
}
```

## Remediation steps
1. Set `ssl_enforcement_enabled = true` (Terraform) or `properties.sslEnforcement = "Enabled"` (ARM/Bicep) on the PostgreSQL server resource.
2. Update application connection strings to require TLS (e.g., `sslmode=require` or `verify-full` for stronger validation), or existing plaintext connections will be rejected once enforcement is enabled.
3. Note: `azurerm_postgresql_server` (single server) is a deprecated SKU family being retired in favor of `azurerm_postgresql_flexible_server`, which has its own equivalent SSL/TLS enforcement setting — prefer flexible server for new deployments.
4. Distribute the appropriate root CA certificate to client applications ahead of enforcing SSL to avoid connection failures during rollout.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerSSLEnforcementEnabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/PostgreSQLServerSSLEnforcementEnabled.py)
- [Azure Database for PostgreSQL SSL connectivity](https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-ssl-connection-security)
