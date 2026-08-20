# CKV_AWS_31: Ensure all data stored in the ElastiCache Replication Group is securely encrypted at transit and has auth token

## Severity
**HIGH** (score: 7.8/10)

Without encryption in transit and an auth token, traffic to and from the ElastiCache replication group can be intercepted or accessed by anyone reachable on the network, exposing potentially sensitive cached data.

## Summary
This check ensures ElastiCache (Redis) replication groups enable in-transit (TLS) encryption and use an auth token (or a user group for RBAC-based access control), so that client-to-cluster traffic and cache access are both protected.

## Applicability
- **IaC frameworks:** Terraform and CloudFormation
- **Resource types:** `aws_elasticache_replication_group` (Terraform), `AWS::ElastiCache::ReplicationGroup` (CloudFormation)

## Why it matters
By default, ElastiCache Redis replication groups transmit data between the client and the cluster (and between cluster nodes) in plaintext. Any party with network-level visibility — a compromised host on the same VPC, a misconfigured security group, or a packet capture on a shared subnet — can read or tamper with cached data in transit, which frequently includes session tokens, PII, or other sensitive application state. Additionally, ElastiCache Redis has no authentication by default: if the security group is ever too permissive, anyone who can reach the endpoint can run arbitrary Redis commands (including `FLUSHALL`, `CONFIG SET`, or data exfiltration via `KEYS`/`DUMP`). Requiring `transit_encryption_enabled` together with an `auth_token` (or a `user_group_ids` RBAC configuration) closes both gaps: traffic is encrypted and unauthenticated commands are rejected.

## How Checkov evaluates this
**Terraform:** Looks at the `aws_elasticache_replication_group` config and requires **both**:
- `transit_encryption_enabled` is present and truthy, **and**
- either `auth_token` or `user_group_ids` is also present.

If both conditions hold, the check **PASSES**; otherwise it **FAILS**.

**CloudFormation:** Same logic against `Properties.TransitEncryptionEnabled`, `Properties.AuthToken`, and `Properties.UserGroupIds` — passes only if `TransitEncryptionEnabled` is `true` and either `AuthToken` or `UserGroupIds` is also present.

## Non-compliant example
```hcl
resource "aws_elasticache_replication_group" "example" {
  replication_group_id = "example-redis"
  description           = "example redis replication group"
  node_type             = "cache.m6g.large"
  num_cache_clusters    = 2
  engine                = "redis"
  engine_version        = "7.0"
  # No transit_encryption_enabled, no auth_token -> plaintext, unauthenticated
}
```

## Remediated example
```hcl
resource "aws_elasticache_replication_group" "example" {
  replication_group_id       = "example-redis"
  description                = "example redis replication group"
  node_type                  = "cache.m6g.large"
  num_cache_clusters         = 2
  engine                     = "redis"
  engine_version             = "7.0"
  transit_encryption_enabled = true               # encrypts client<->cluster traffic
  auth_token                 = var.redis_auth_token # requires TLS; rotate via variable/secret store
}
```

## Remediation steps
1. Set `transit_encryption_enabled = true` (Terraform) or `TransitEncryptionEnabled: true` (CloudFormation).
2. Provide an `auth_token` (16-128 characters, generated and stored in a secrets manager — never hard-coded) or configure `user_group_ids` for Redis 6.x+ RBAC-based access control.
3. Note that enabling transit encryption on an **existing** replication group typically requires an in-place upgrade or a replacement (blue/green) deployment, depending on the current Redis engine version — plan for a maintenance window.
4. Ensure client applications are updated to connect over `rediss://` (TLS) and supply the auth token, otherwise they will fail to connect after the change.
5. Rotate the auth token periodically and store it in AWS Secrets Manager or SSM Parameter Store rather than plain Terraform variables.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticacheReplicationGroupEncryptionAtTransitAuthToken.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ElasticacheReplicationGroupEncryptionAtTransitAuthToken.py
- AWS docs: https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html
