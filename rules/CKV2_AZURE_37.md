# CKV2_AZURE_37: Ensure Azure MariaDB server is using latest TLS (1.2)

## Severity
**LOW** (score: 2.0/10)

Allowing a TLS version below 1.2 (or leaving it unenforced) on a MariaDB server weakens encryption-in-transit for a database that may hold sensitive data, exposing connections to protocol-downgrade and known TLS 1.0/1.1 weaknesses.

## Summary
This check ensures an Azure Database for MariaDB server both enforces SSL for client connections and, if a minimum TLS version is explicitly set, requires TLS 1.2 rather than an older, weaker version.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (implemented as a graph-based check, not a Python resource check)
- **Resource type:** `azurerm_mariadb_server`

## Why it matters
Azure Database for MariaDB accepts encrypted connections, but administrators can weaken this posture in two independent ways: disabling SSL enforcement entirely (`ssl_enforcement_enabled = false`), which allows plaintext connections vulnerable to network eavesdropping and credential interception; or leaving SSL enforced but permitting an outdated minimum TLS version (TLS 1.0/1.1), which are deprecated protocols with known cryptographic weaknesses (e.g., BEAST, POODLE-adjacent issues) and are no longer considered secure by PCI-DSS and most compliance frameworks. An attacker positioned on the network path (e.g., via ARP spoofing or a compromised intermediate router) could downgrade a session to a weaker cipher/protocol and intercept or tamper with data in transit, including database credentials and query contents.

## How Checkov evaluates this
This is a Terraform graph-based JSON policy. It evaluates to PASS only when **all** of the following hold for an `azurerm_mariadb_server` resource:
1. `ssl_enforcement_enabled` attribute exists.
2. `ssl_enforcement_enabled` equals `"true"` (case-insensitive).
3. Either `ssl_minimal_tls_version_enforced` does not exist (Azure's default is TLS 1.2 in that case) **or** it explicitly equals `"TLS1_2"`.

If SSL enforcement is missing/false, or if a minimum TLS version is explicitly set to anything other than TLS 1.2 (e.g., `TLS1_0` or `TLS1_1`), the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_mariadb_server" "example" {
  name                = "example-mariadb"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadmin"
  administrator_login_password = var.mariadb_password

  sku_name   = "B_Gen5_2"
  storage_mb = 51200
  version    = "10.2"

  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_0"
}
```

## Remediated example
```hcl
resource "azurerm_mariadb_server" "example" {
  name                = "example-mariadb"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadmin"
  administrator_login_password = var.mariadb_password

  sku_name   = "B_Gen5_2"
  storage_mb = 51200
  version    = "10.2"

  ssl_enforcement_enabled          = true       # enforce SSL/TLS on all connections
  ssl_minimal_tls_version_enforced = "TLS1_2"    # reject TLS 1.0/1.1 handshakes
}
```

## Remediation steps
1. Set `ssl_enforcement_enabled = true` on every `azurerm_mariadb_server` resource.
2. Set `ssl_minimal_tls_version_enforced = "TLS1_2"` explicitly (or omit it, since Azure's default is TLS 1.2) — never set it to `TLS1_0` or `TLS1_1`.
3. Update client connection strings/drivers to negotiate TLS 1.2 if they currently pin to an older version.
4. Note: Azure Database for MariaDB is on a retirement path (Microsoft has announced end-of-life); consider migrating to Azure Database for MySQL Flexible Server as a longer-term remediation.
5. Changing `ssl_enforcement_enabled` may require an `apply` that updates the server in place; verify no active connections are dropped unexpectedly during rollout.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureMariaDBserverUsingTLS_1_2.json)
