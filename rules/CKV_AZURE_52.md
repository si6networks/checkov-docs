# CKV_AZURE_52: Ensure MSSQL is using the latest version of TLS encryption

## Severity
**MEDIUM** (score: 5.0/10)

Permitting TLS versions below 1.2 on an Azure SQL server allows database connections to negotiate weak, deprecated encryption, exposing sensitive query and authentication traffic to interception.

## Summary
This check verifies that an Azure SQL (MSSQL) server enforces a minimum TLS version of 1.2 (or higher) for client connections, rejecting older, weaker TLS protocol negotiations.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_mssql_server`
- **ARM templates**: `Microsoft.Sql/servers`
- **Bicep**: `Microsoft.Sql/servers`

## Why it matters
SQL Server connections carry query traffic and result sets that frequently include highly sensitive data — customer records, financial data, credentials stored in application tables. Older TLS versions (1.0, 1.1) have documented cryptographic weaknesses and are subject to protocol-downgrade and cipher-suite attacks that can allow an on-path attacker to intercept or tamper with database traffic. Because Azure SQL is commonly accessed by applications running outside a fully isolated network (across regions, from on-prem via ExpressRoute/VPN, or by third-party BI/reporting tools), enforcing a strong minimum TLS version closes off a straightforward network-layer attack vector against what is often an organization's most sensitive data store. This is also required by most compliance regimes (PCI-DSS, HIPAA, SOC 2) that mandate strong transport encryption for data containing regulated information.

## How Checkov evaluates this
Implemented as a generic value check with a `missing_block_result` override so that an entirely absent setting is treated as a failure (not "unknown"):
- **ARM**: Inspects `properties.minimalTlsVersion`. PASSES if the value is any of `"1.2"`, `1.2` (numeric), `"1.3"`, or `1.3` (numeric). If the property is missing altogether, the check explicitly FAILS (via `missing_block_result=CheckResult.FAILED`) rather than defaulting to unknown/pass.
- **Terraform**: Inspects `minimum_tls_version`. PASSES only if the value equals `"1.2"`.

## Non-compliant example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.admin_password

  minimum_tls_version = "1.0"
}
```

## Remediated example
```hcl
resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.admin_password

  minimum_tls_version = "1.2"
}
```

## Remediation steps
1. Set `minimum_tls_version = "1.2"` on the `azurerm_mssql_server` resource, or `properties.minimalTlsVersion = "1.2"` in ARM/Bicep.
2. Do not omit the property entirely — Checkov (and, more importantly, Azure's own security posture) treats an unset minimum TLS version as non-compliant, since it may default to a weaker or unspecified negotiation floor.
3. Verify that client drivers/ODBC/JDBC versions in use by connecting applications support TLS 1.2 before enforcing — older driver versions may need to be upgraded.
4. This setting can typically be changed in place without server recreation, but active connections using unsupported protocol versions will be rejected once the change propagates.
5. Combine with Azure SQL auditing and Advanced Threat Protection for defense-in-depth beyond transport encryption alone.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/MSSQLServerMinTLSVersion.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MSSQLServerMinTLSVersion.py)
- [Azure SQL Database minimal TLS version documentation](https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings#minimal-tls-version)
