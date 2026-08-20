# CKV_AZURE_89: Ensure that Azure Cache for Redis disables public network access
## Severity
**HIGH** (score: 7.5/10)

Leaving Azure Cache for Redis reachable from the public internet exposes an in-memory data store that frequently holds session tokens, cached credentials, or sensitive application state to remote attack and data-exfiltration attempts.

## Summary
This check verifies that Azure Cache for Redis instances have public network access disabled, forcing all connectivity through private endpoints/VNet integration instead of the public internet.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_redis_cache` (inspects `public_network_access_enabled`)
- **ARM templates**: `Microsoft.Cache/redis` (inspects `properties.publicNetworkAccess`)
- **Bicep**: resources compiling to `Microsoft.Cache/redis`

## Why it matters
Redis is frequently used to cache session tokens, authentication state, rate-limit counters, and other sensitive application data, and by default Redis has weak/no built-in transport authentication compared to a full database engine. If `publicNetworkAccess` is left enabled:
- The cache endpoint is reachable from the public internet, subject only to firewall rules and (if configured) access keys — both of which are frequently misconfigured or leaked.
- An attacker who obtains or brute-forces an access key can read/write cached data directly from the internet without ever touching the internal network.
- It expands the internet-facing attack surface unnecessarily, since Redis is normally an internal-only dependency of an application, not a customer-facing endpoint.

Disabling public network access and requiring Private Link / VNet access ensures the cache is only reachable from within the trusted network perimeter, eliminating an entire class of internet-based attacks against it.

## How Checkov evaluates this
- **Terraform**: `BaseResourceValueCheck` inspects `public_network_access_enabled` and expects it to equal `false`. Any other value (including the default `true`) fails.
- **ARM**: `BaseResourceValueCheck` inspects `properties.publicNetworkAccess` and expects the string `"Disabled"`. Any other value (including `"Enabled"` or absence) fails.

## Non-compliant example
```hcl
resource "azurerm_redis_cache" "example" {
  name                = "example-cache"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"

  public_network_access_enabled = true
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

  public_network_access_enabled = false  # <-- forces private-only access
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess = "Disabled"` (ARM/Bicep) on the Redis cache resource.
2. Create a Private Endpoint (`azurerm_private_endpoint`) connecting the cache into your VNet so applications can still reach it privately.
3. Update application connection strings/DNS if you previously relied on the public hostname resolving directly — with Private Link, private DNS zone integration is required for name resolution to resolve to the private IP.
4. This is a property update, not a resource replacement, so it can typically be applied without recreating the cache — but validate connectivity from all consumers before disabling public access in production, since it will immediately cut off internet-based clients.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RedisCachePublicNetworkAccessEnabled.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/RedisCachePublicNetworkAccessEnabled.py
