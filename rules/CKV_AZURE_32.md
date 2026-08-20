# CKV_AZURE_32: Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server

## Severity
**LOW** (score: 2.0/10)

Disabling connection throttling removes a control that slows down repeated failed login attempts, weakening (but not eliminating) resistance to brute-force credential attacks against the PostgreSQL server.

## Summary
This check ensures the PostgreSQL server configuration parameter `connection_throttling` is turned on, enabling protection against rapid repeated failed-login attempts.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, ARM, Bicep (via shared entities)
- **Resource types:** `Microsoft.DBforPostgreSQL/servers/configurations` (and generic `configurations` with `parent_type = Microsoft.DBforPostgreSQL/servers`), `azurerm_postgresql_configuration`

## Why it matters
`connection_throttling` on Azure Database for PostgreSQL enables server-side delay/throttling of connection attempts after repeated failed logins from the same source, which directly mitigates brute-force and credential-stuffing attacks against the database's authentication endpoint. Without it, an attacker (or a compromised/misbehaving client) can hammer the login endpoint with unlimited rapid authentication attempts, either succeeding via brute force against weak credentials or exhausting server connection resources in a denial-of-service pattern. Enabling this parameter adds a low-cost, built-in rate-limiting defense at the database layer, complementing (not replacing) network-level controls like firewall rules and Azure AD authentication.

## How Checkov evaluates this
**ARM check**: applies to the `configurations` resource named `connection_throttling` under `Microsoft.DBforPostgreSQL/servers`. **PASS** if `properties.value` (case-insensitive) equals `"on"`; **FAIL** if set to anything else (e.g., `"off"`); **FAIL** if no `type` is present at all.

**Terraform check**: inspects `azurerm_postgresql_configuration`'s `name`/`value`. **FAIL** only if `name == "connection_throttling"` and `value == "off"`; **PASS** otherwise.

## Non-compliant example
```hcl
resource "azurerm_postgresql_configuration" "connection_throttling" {
  name                = "connection_throttling"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "off"
}
```

## Remediated example
```hcl
resource "azurerm_postgresql_configuration" "connection_throttling" {
  name                = "connection_throttling"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "on"   # was "off"
}
```

## Remediation steps
1. Set the `azurerm_postgresql_configuration` resource with `name = "connection_throttling"` to `value = "on"`.
2. In ARM/Bicep, set the nested `configurations` resource's `properties.value` to `"on"` for the `connection_throttling` parameter.
3. Combine with strong password policies, Azure AD authentication where possible, and network-level firewall rules/private endpoints — connection throttling is a defense-in-depth layer, not a substitute for those controls.
4. Monitor for legitimate high-frequency connection patterns (e.g., serverless functions opening many short-lived connections) that could be mistaken for abuse under throttling; consider connection pooling to reduce false-positive throttling impact.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerConnectionThrottlingEnabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/PostgreSQLServerConnectionThrottlingEnabled.py)
- [Azure Database for PostgreSQL server parameters](https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-servers)
