# CKV_AWS_29: Ensure all data stored in the ElastiCache Replication Group is securely encrypted at rest
## Severity
**LOW** (score: 2.0/10)

Disabling at-rest encryption on an ElastiCache Replication Group leaves cached data, which frequently includes session tokens or application data, stored in plaintext and readable if the underlying storage is ever accessed or compromised.

## Summary
This check fails when an ElastiCache Replication Group does not enable at-rest encryption, leaving cached data unprotected against unauthorized access to the underlying storage.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Frameworks:** Terraform, CloudFormation
- **Resources:** `aws_elasticache_replication_group` (Terraform), `AWS::ElastiCache::ReplicationGroup` (CloudFormation)

## Why it matters
ElastiCache Replication Groups (Redis) can persist data to disk in several scenarios: during backup/snapshot creation, swap-to-disk under memory pressure, and for replication/failover data transfer between nodes. Without at-rest encryption, any of this on-disk data — including cached session tokens, API responses, user data, or application secrets cached for performance — is stored unencrypted at the storage layer. If the underlying EBS volumes, snapshots, or backup artifacts are ever accessed outside normal channels (e.g., through a misconfigured snapshot share, compromised AWS credentials with storage-level access, or improper disposal of underlying media), the cached data is directly readable. Because caching layers are often treated as "ephemeral, low sensitivity" by developers, they are one of the more commonly overlooked places sensitive data ends up unintentionally persisted without encryption controls applied elsewhere in the stack.

## How Checkov evaluates this
**Terraform:** `BaseResourceValueCheck` inspects the `at_rest_encryption_enabled` attribute on `aws_elasticache_replication_group`. It passes when `true`; fails when missing or `false`.

**CloudFormation:** `BaseResourceValueCheck` inspects `Properties/AtRestEncryptionEnabled` on `AWS::ElastiCache::ReplicationGroup`. It passes when `true`; fails when missing or `false`.

## Non-compliant example
```hcl
resource "aws_elasticache_replication_group" "example" {
  replication_group_id = "example-cache"
  description           = "example redis cluster"
  node_type             = "cache.r6g.large"
  num_cache_clusters    = 2
  engine                = "redis"
  # at_rest_encryption_enabled not set -> defaults to false
}
```

## Remediated example
```hcl
resource "aws_elasticache_replication_group" "example" {
  replication_group_id       = "example-cache"
  description                 = "example redis cluster"
  node_type                   = "cache.r6g.large"
  num_cache_clusters          = 2
  engine                      = "redis"
  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
}
```

## Remediation steps
1. Set `at_rest_encryption_enabled = true` (Terraform) or `AtRestEncryptionEnabled: true` (CloudFormation) on the replication group.
2. Note that at-rest encryption **cannot be enabled on an existing, already-running replication group** — it must be set at creation time. Enabling it on an existing cluster requires creating a new encrypted replication group and migrating data (e.g., via snapshot restore into a new encrypted cluster), which involves a cutover.
3. While making this change, also enable `transit_encryption_enabled` (in-transit/TLS encryption) for defense-in-depth, since at-rest encryption alone doesn't protect data moving over the network.
4. Optionally specify a customer-managed KMS key via `kms_key_id` (Terraform) instead of the default AWS-managed key, if compliance requires customer key control.
5. Plan the migration during a maintenance window since replacing the replication group is a disruptive, stateful operation for any application relying on cache warm-up performance.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticacheReplicationGroupEncryptionAtRest.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ElasticacheReplicationGroupEncryptionAtRest.py
- AWS docs: https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html
