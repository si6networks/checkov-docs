# CKV_AZURE_148: Ensure Redis Cache is using the latest version of TLS encryption

## Severity
**MEDIUM** (score: 5.5/10)

Allowing older TLS versions on Redis Cache weakens transport encryption for cached data (which can include session/auth data), but exploitation requires an active network position and a still-viable protocol downgrade, not direct exposure or credential leakage.

## Summary
This check ensures that an Azure Redis Cache instance requires clients to connect using TLS 1.2 (or later) rather than an older, weaker TLS/SSL version.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_redis_cache`

## Why it matters
Redis Cache traffic can carry sensitive application state, session tokens, and cached credentials. Older TLS versions (1.0, 1.1) and SSL are subject to well-known cryptographic weaknesses (e.g. POODLE, BEAST) and are deprecated by most security standards (PCI-DSS, NIST). If a Redis Cache instance is left on a lower minimum TLS version, or the setting is omitted, an attacker capable of intercepting network traffic (e.g. via a compromised intermediate network device or a downgrade attack) can force a weaker handshake and potentially decrypt or tamper with the exposed cache traffic. Enforcing TLS 1.2 as the floor removes this downgrade path.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `minimum_tls_version` attribute on `azurerm_redis_cache`:
- **FAIL** if the attribute is missing entirely (`missing_block_result=CheckResult.FAILED`).
- **FAIL** if `minimum_tls_version` is set to anything other than `"1.2"`.
- **PASS** only when `minimum_tls_version = "1.2"`.

## Non-compliant example
```hcl
resource "azurerm_redis_cache" "example" {
  name                = "example-cache"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"

  # minimum_tls_version omitted -> defaults may allow older TLS, check FAILS
}
```

## Remediated example
```hcl
resource "azurerm_redis_cache" "example" {
  name                = "example-cache"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"

  minimum_tls_version = "1.2"  # enforces TLS 1.2 as the minimum
}
```

## Remediation steps
1. Add `minimum_tls_version = "1.2"` to every `azurerm_redis_cache` resource block.
2. Redeploy/apply — this is typically an in-place update and does not require replacing the cache instance, but confirm with `terraform plan` since some Azure API versions may still show it as requiring a resource update.
3. Ensure client applications and libraries connecting to Redis support TLS 1.2 before enforcing this, or connections will be rejected.
4. Audit any existing caches for clients still using SSL/TLS 1.0/1.1 and upgrade client libraries as needed.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RedisCacheMinTLSVersion.py)
- [Azure Cache for Redis TLS documentation](https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-remove-tls-10-11)
