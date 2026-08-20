# CKV_AWS_191: Ensure ElastiCache replication group is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

ElastiCache replication groups often cache session tokens or application data, and while this check only enforces CMK usage over the AWS-managed default, losing that key control represents a moderate exposure for cached sensitive data.

## Summary
This check requires that an `aws_elasticache_replication_group` resource specify a customer-managed KMS key (`kms_key_id`) for at-rest encryption instead of the AWS-managed default key.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_elasticache_replication_group`
- **Check type:** resource (attribute-value check)

## Why it matters
ElastiCache (Redis) replication groups are frequently used as session stores, caching layers for user data, or even as a lightweight message broker, and can hold sensitive data such as session tokens, cached PII, or application secrets in memory-backed but disk-persisted snapshots/backups. Without a customer-managed key, at-rest encryption (of backups/snapshots) falls back to the AWS-managed default key, denying your organization the ability to enforce a custom key policy, audit key usage per application, or revoke access instantly during an incident. Because cache data often mirrors data from a primary datastore, weak encryption governance on the cache can become the weaker link an attacker exploits to access data that is otherwise well-protected in the primary database.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `kms_key_id` attribute of `aws_elasticache_replication_group`. It expects `ANY_VALUE` — any non-empty value passes. If `kms_key_id` is absent, the check FAILS (note: `at_rest_encryption_enabled = true` is required for `kms_key_id` to take effect at all — that requirement is a separate, related Checkov rule).

## Non-compliant example
```hcl
resource "aws_elasticache_replication_group" "example" {
  replication_group_id       = "app-cache"
  description                = "app redis cache"
  node_type                  = "cache.r6g.large"
  num_cache_clusters         = 2
  engine                     = "redis"
  at_rest_encryption_enabled = true
  # kms_key_id not set -- uses AWS-managed default key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "elasticache" {
  description             = "CMK for ElastiCache encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_elasticache_replication_group" "example" {
  replication_group_id       = "app-cache"
  description                = "app redis cache"
  node_type                  = "cache.r6g.large"
  num_cache_clusters         = 2
  engine                     = "redis"
  at_rest_encryption_enabled = true
  kms_key_id                 = aws_kms_key.elasticache.arn  # customer managed key
}
```

## Remediation steps
1. Create or select a customer-managed KMS key with a key policy scoped to the ElastiCache service and the application roles consuming the cache.
2. Ensure `at_rest_encryption_enabled = true` is set (a prerequisite), then add `kms_key_id` pointing to the CMK.
3. Note: enabling/changing at-rest encryption and its KMS key on an existing replication group typically requires creating a new replication group and migrating (via snapshot restore), since these settings are immutable post-creation — plan for a cutover window.
4. Also enable `transit_encryption_enabled = true` for encryption in transit, as at-rest encryption alone does not protect data moving between clients and the cache nodes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticacheReplicationGroupEncryptedWithCMK.py)
- [AWS ElastiCache for Redis at-rest encryption documentation](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html)
