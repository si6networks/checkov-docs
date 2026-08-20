# CKV_AZURE_230: Standard Replication should be enabled

## Severity
**HIGH** (score: 7.5/10)

Lack of standard replication for Redis Cache is a high-availability weakness that can cause service downtime on VM failure but does not itself expose or compromise data.

## Summary
This check ensures an Azure Cache for Redis instance uses the Standard or Premium SKU tier (which run on a replicated pair of VMs) rather than the Basic tier (single VM, no replication).

## Applicability
- **Terraform**: `azurerm_redis_cache` resources — inspects the `sku_name` attribute.

## Why it matters
The Basic SKU tier for Azure Cache for Redis runs on a single dedicated VM with no replica. If that VM has a hardware failure, host reboot for platform maintenance, or any other outage, the cache goes down completely with no automatic failover, taking with it any application functionality that depends on cache availability (session storage, rate limiting, feature flags, output caching, pub/sub messaging, etc.). Depending on the application's cache dependency, this can range from a performance degradation to a full outage (e.g., if sessions are stored only in Redis and it becomes unreachable, every logged-in user could be signed out or requests could error).

Standard and Premium tiers run two Redis nodes (primary/replica) in an active/standby configuration with automatic failover, so both planned maintenance and unplanned VM failures are absorbed without customer-visible downtime in most cases.

## How Checkov evaluates this
`BaseResourceValueCheck` inspecting the `sku_name` attribute on `azurerm_redis_cache`. The check PASSES only if `sku_name` is exactly `"Standard"` or `"Premium"`; it FAILS for `"Basic"` (or any other value, including if unset — Terraform requires `sku_name`, but Checkov flags anything outside the expected list).

## Non-compliant example
```hcl
resource "azurerm_redis_cache" "example" {
  name                = "example-cache"
  location            = azurerm_resource_group.example.location
  resource_group_name  = azurerm_resource_group.example.name
  capacity            = 1
  family              = "C"
  sku_name            = "Basic"   # single VM, no replica -> FAILS
  minimum_tls_version = "1.2"
}
```

## Remediated example
```hcl
resource "azurerm_redis_cache" "example" {
  name                = "example-cache"
  location            = azurerm_resource_group.example.location
  resource_group_name  = azurerm_resource_group.example.name
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"   # replicated pair -> PASSES
  minimum_tls_version = "1.2"
}
```

## Remediation steps
1. Change `sku_name` from `"Basic"` to `"Standard"` (or `"Premium"` for advanced features like clustering, persistence, and VNet injection).
2. Note that changing the SKU tier on an existing cache typically requires recreating the resource (Terraform will show a forced replacement in the plan) — schedule this during a maintenance window since existing cached data will be lost and clients will briefly lose connectivity.
3. For workloads needing geo-replication, data persistence (RDB/AOF), clustering, or private networking, use the Premium tier instead of Standard.
4. Update `family` and `capacity` values as needed — Standard/Premium tiers use different `family` letter codes (`C` for Standard, `P` for Premium) and capacity ranges than Basic.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RedisCacheStandardReplicationEnabled.py
- Azure docs: https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-failover
