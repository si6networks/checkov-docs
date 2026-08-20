# CKV_AWS_30: Ensure all data stored in the ElastiCache Replication Group is securely encrypted at transit
## Severity
**HIGH** (score: 7.5/10)

This check verifies ElastiCache replication group in-transit encryption; without it, cache traffic (which often carries session tokens, credentials, or cached sensitive application data) can be intercepted by anyone with network visibility.

## Summary
This check ensures an ElastiCache Replication Group has in-transit (TLS) encryption enabled, checking `transit_encryption_enabled` in Terraform (`aws_elasticache_replication_group`) or `TransitEncryptionEnabled` in CloudFormation (`AWS::ElastiCache::ReplicationGroup`).

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** Terraform, CloudFormation
- **Resource types:** `aws_elasticache_replication_group` (Terraform), `AWS::ElastiCache::ReplicationGroup` (CloudFormation)

## Why it matters
ElastiCache (typically Redis) replication groups are commonly used to cache session tokens, database query results, rate-limit counters, and sometimes sensitive application state. Without transit encryption, all traffic between application clients and the cache nodes — and between replica nodes themselves — travels in plaintext over the network. Any attacker positioned on the same VPC subnet, a compromised neighboring instance, a misconfigured security group, or someone able to perform ARP spoofing/traffic mirroring within the VPC can passively sniff this traffic and recover cached credentials, session identifiers, or business data. This is especially risky for cache-based session stores, where interception of a session token can lead directly to account takeover.

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck` checks looking for a boolean-true value:
- **Terraform:** inspects `transit_encryption_enabled` on `aws_elasticache_replication_group`. **PASS** if `true`; **FAIL** if absent (default `false`) or explicitly `false`.
- **CloudFormation:** inspects `Properties.TransitEncryptionEnabled` on `AWS::ElastiCache::ReplicationGroup`. **PASS** if `true`; **FAIL** if absent or `false`.

## Non-compliant example
```hcl
resource "aws_elasticache_replication_group" "cache" {
  replication_group_id = "app-cache"
  description           = "App session cache"
  node_type             = "cache.r6g.large"
  num_cache_clusters    = 2
  engine                = "redis"
  # transit_encryption_enabled not set -> defaults to false, check FAILS
}
```

## Remediated example
```hcl
resource "aws_elasticache_replication_group" "cache" {
  replication_group_id       = "app-cache"
  description                = "App session cache"
  node_type                  = "cache.r6g.large"
  num_cache_clusters         = 2
  engine                     = "redis"
  transit_encryption_enabled = true   # encrypt data in transit (TLS)
  auth_token                 = var.redis_auth_token  # recommended alongside transit encryption
}
```

## Remediation steps
1. Set `transit_encryption_enabled = true` (Terraform) or `TransitEncryptionEnabled: true` (CloudFormation) on the replication group.
2. Note: enabling transit encryption on Redis requires the `auth_token` parameter to be set (Redis AUTH) in many configurations, and typically **cannot be enabled in-place on an existing replication group** without recreating it — plan for a maintenance window or blue/green cutover.
3. Update all client application connection strings/configuration to use `rediss://` (TLS) rather than `redis://`, and ensure client libraries are configured to validate the ElastiCache-issued TLS certificate.
4. Pair this with `at_rest_encryption_enabled = true` (a separate but related setting) for full encryption coverage at rest and in transit.
5. Verify application-side Redis client library versions support TLS to avoid connectivity breakage after the change.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ElasticacheReplicationGroupEncryptionAtTransit.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticacheReplicationGroupEncryptionAtTransit.py)
