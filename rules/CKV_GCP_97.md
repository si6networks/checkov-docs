# CKV_GCP_97: Ensure Memorystore for Redis uses in-transit encryption
## Severity
**LOW** (score: 2.0/10)

Without in-transit encryption, traffic to and from a Redis instance (which may hold session tokens, cached credentials, or sensitive application data) can be intercepted by anyone with network path access.

## Summary
This check requires `google_redis_instance` resources to set `transit_encryption_mode = "SERVER_AUTHENTICATION"`, so traffic between clients and the Redis instance is TLS-encrypted rather than sent in plaintext.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_redis_instance`
- **Check type:** resource (attribute-value check)

## Why it matters
By default, Memorystore for Redis transmits all traffic — including the AUTH credential (if enabled) and every cached value read or written — in plaintext over the VPC network. Any party with network visibility into the traffic path (a compromised host on the same VPC, a misconfigured peering/packet-mirroring setup, or an attacker who has gained a foothold in the network) can passively sniff session tokens, cached PII, rate-limiting counters, or other application state carried through Redis, and can also capture the AUTH string itself if it's sent unencrypted, defeating the protection that `auth_enabled` (CKV_GCP_95) is meant to provide. Enabling `SERVER_AUTHENTICATION` (TLS) mode ensures the wire traffic is encrypted, closing this passive-sniffing avenue and aligning with encryption-in-transit requirements common in compliance frameworks for any data store handling sensitive cached data.

## How Checkov evaluates this
The check (`MemorystoreForRedisInTransitEncryption`, a `BaseResourceValueCheck`) inspects the `transit_encryption_mode` attribute on `google_redis_instance`, expecting the literal value `"SERVER_AUTHENTICATION"`.
- **PASS**: `transit_encryption_mode = "SERVER_AUTHENTICATION"`.
- **FAIL**: `transit_encryption_mode` is absent or set to `"DISABLED"` (the default).

## Non-compliant example
```hcl
resource "google_redis_instance" "cache" {
  name           = "app-cache"
  tier           = "STANDARD_HA"
  memory_size_gb = 5
  region         = "us-central1"
  auth_enabled   = true
  # transit_encryption_mode not set -> traffic sent in plaintext
}
```

## Remediated example
```hcl
resource "google_redis_instance" "cache" {
  name                    = "app-cache"
  tier                    = "STANDARD_HA"
  memory_size_gb          = 5
  region                  = "us-central1"
  auth_enabled            = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"
}
```

## Remediation steps
1. Set `transit_encryption_mode = "SERVER_AUTHENTICATION"` on the `google_redis_instance` resource.
2. Update application Redis clients to connect over TLS (most Redis client libraries require an explicit TLS/SSL flag and, in some cases, the server CA certificate, retrievable via the instance's `server_ca_certs` attribute).
3. This setting is typically only configurable at instance creation for Memorystore Redis — changing it on an existing instance usually requires recreating the instance; plan a cache-rebuild/cutover window (acceptable for most caches, since Redis here is generally used as a cache rather than a system of record).
4. Verify client-side TLS overhead is acceptable for latency-sensitive workloads and load-test after the change.
5. Pair with `auth_enabled = true` (CKV_GCP_95) so both the credential and the data itself are protected in transit.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/MemorystoreForRedisInTransitEncryption.py
- GCP docs: https://cloud.google.com/memorystore/docs/redis/in-transit-encryption
