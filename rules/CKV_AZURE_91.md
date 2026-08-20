# CKV_AZURE_91: Ensure that only SSL are enabled for Cache for Redis
## Severity
**LOW** (score: 2.0/10)

Enabling the non-SSL port on Azure Cache for Redis permits cleartext transmission of cached data and credentials, exposing sensitive in-transit data to network eavesdropping and man-in-the-middle attacks.

## Summary
This check verifies that an Azure Cache for Redis instance does not have the legacy non-SSL (unencrypted) port enabled, ensuring all client connections use TLS.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_redis_cache` (inspects `enable_non_ssl_port`)

## Why it matters
Azure Cache for Redis can optionally expose an additional plaintext (non-TLS) port (6379) alongside the default TLS port (6380). If `enable_non_ssl_port` is left on:
- Traffic to/from the cache — including the access key used for authentication and any cached application data (session tokens, user data, rate-limit counters) — travels unencrypted over the network.
- An attacker positioned on the network path (e.g. via ARP spoofing on a shared VNet, a compromised peer VM, or a misconfigured routing path) can passively sniff traffic and capture the Redis access key or sensitive cached values in plaintext.
- It undermines defense-in-depth: even if network segmentation is otherwise sound, an unencrypted transport removes a layer of protection against internal threats and lateral movement.

Disabling the non-SSL port forces every client to connect via TLS, protecting both the authentication key and cached data in transit.

## How Checkov evaluates this
`BaseResourceValueCheck` inspects the `enable_non_ssl_port` attribute and expects it to equal `false`. If the attribute is **absent entirely**, the check is configured with `missing_block_result=CheckResult.PASSED` — meaning omitting it entirely passes (since the Terraform provider's default is `false`/disabled). The check only FAILS when `enable_non_ssl_port` is explicitly set to `true`.

## Non-compliant example
```hcl
resource "azurerm_redis_cache" "example" {
  name                = "example-cache"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"

  enable_non_ssl_port = true   # <-- allows unencrypted connections
}
```

## Remediated example
```hcl
resource "azurerm_redis_cache" "example" {
  name                = "example-cache"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"

  enable_non_ssl_port = false  # <-- or simply omit the attribute
}
```

## Remediation steps
1. Remove `enable_non_ssl_port = true` from the `azurerm_redis_cache` resource, or explicitly set it to `false`.
2. Update all client applications to connect on the TLS port (6380) using a TLS-capable Redis client library.
3. Verify the minimum TLS version setting (`minimum_tls_version`) is also set to a modern value (e.g. `"1.2"`) for defense in depth.
4. This is a non-disruptive configuration change for clients already using TLS; clients still relying on the plaintext port will lose connectivity and must be updated first.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RedisCacheEnableNonSSLPort.py
