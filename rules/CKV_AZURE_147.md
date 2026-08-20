# CKV_AZURE_147: Ensure PostgreSQL is using the latest version of TLS encryption
## Severity
**LOW** (score: 2.0/10)

Permitting PostgreSQL connections below TLS 1.2 allows clients to negotiate outdated, cryptographically weaker protocol versions, exposing database traffic (including credentials and query data) to interception or downgrade attacks.

## Summary
This check ensures an Azure Database for PostgreSQL (single server) enforces a minimum TLS version of 1.2 for client connections, rather than allowing older, weaker TLS versions or leaving the setting unconfigured.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_postgresql_server` resource, attribute `ssl_minimal_tls_version_enforced`.

## Why it matters
Database connections often carry highly sensitive data — credentials, business records, PII — and if the server accepts connections negotiated with TLS 1.0 or 1.1 (both deprecated due to known cryptographic weaknesses), that traffic is vulnerable to protocol downgrade attacks and weaker cipher suites, undermining confidentiality and integrity guarantees for data in transit between application and database. Since PostgreSQL servers are frequently reachable from application tiers across network boundaries (VNets, on-prem via VPN, sometimes public endpoints with firewall rules), enforcing a strong minimum TLS version closes off a class of network-level interception/downgrade attacks regardless of what TLS version a misconfigured or outdated client library might otherwise attempt to negotiate down to.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting `ssl_minimal_tls_version_enforced`, expecting the exact string `'TLS1_2'` to PASS. It is constructed with `missing_block_result=CheckResult.FAILED` — meaning if the attribute is not set in the Terraform configuration at all, the check explicitly FAILS, rather than assuming a safe provider default. (This differs from some sibling TLS checks that pass on a missing block; here the absence of an explicit setting is treated as non-compliant.)

## Non-compliant example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "example-psqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladmin"
  administrator_login_password = var.admin_password
  sku_name                     = "GP_Gen5_2"
  version                      = "11"
  ssl_enforcement_enabled       = true
  # ssl_minimal_tls_version_enforced not set -- FAILS (missing_block_result = FAILED)
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_server" "example" {
  name                = "example-psqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladmin"
  administrator_login_password = var.admin_password
  sku_name                     = "GP_Gen5_2"
  version                      = "11"
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"  # explicitly enforces modern TLS only
}
```

## Remediation steps
1. Explicitly set `ssl_minimal_tls_version_enforced = "TLS1_2"` on every `azurerm_postgresql_server` resource — do not rely on omitting the attribute, since this check fails closed on a missing value.
2. Ensure `ssl_enforcement_enabled = true` is also set; enforcing a minimum TLS version has no effect if SSL/TLS itself is not required for connections.
3. Verify all client applications, drivers, and connection pooling tools support TLS 1.2 before enforcing it, to avoid connection failures for legacy clients.
4. Note: Azure Database for PostgreSQL single server is being retired/deprecated in favor of Flexible Server — for new deployments use `azurerm_postgresql_flexible_server`, which handles TLS enforcement differently (via server parameters), and this specific check does not cover that resource type.
5. This is a configuration-level change on the existing server and typically does not require resource recreation, but validate connectivity from all dependent applications after applying.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLMinTLSVersion.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-ssl-connection-security
