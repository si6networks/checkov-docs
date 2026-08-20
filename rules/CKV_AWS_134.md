# CKV_AWS_134: Ensure that Amazon ElastiCache Redis clusters have automatic backup turned on

## Severity
**LOW** (score: 2.0/10)

Disabled ElastiCache automatic backups risk permanent data loss on cluster failure but do not themselves expose data or credentials to unauthorized parties.

## Summary
This check requires ElastiCache Redis clusters to set `snapshot_retention_limit` to a non-zero value so that automatic daily snapshots are retained.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_elasticache_cluster` (only evaluated for Redis; clusters with `engine = "memcached"` return UNKNOWN since Memcached has no backup/snapshot capability)

## Why it matters
Without automatic backups, an ElastiCache Redis cluster has no recovery path if the cluster fails, is accidentally deleted, or its data is corrupted (e.g., a bad `FLUSHALL`, an application bug that overwrites cached session/state data, or a compromised instance issuing destructive commands). Depending on how Redis is used in the architecture, this can mean losing session state, rate-limiting counters, real-time application state, or cached data that is expensive/slow to regenerate, and can also mean losing data if Redis is used as more than a pure cache (e.g., a lightweight primary store, queue, or leaderboard). Automatic snapshots provide a recovery point without manual intervention.

## How Checkov evaluates this
The check (`ElasticCacheAutomaticBackup`, based on `BaseResourceNegativeValueCheck`) treats `0` as a forbidden value for `snapshot_retention_limit`:
- If `engine == "memcached"`, result is **UNKNOWN** (Memcached does not support snapshotting).
- Otherwise: **FAIL** if `snapshot_retention_limit` is explicitly `0`.
- If the attribute is missing entirely, the check's `missing_attribute_result` is explicitly set to **FAILED** — so omitting the attribute also fails (unlike many other value checks in Checkov, this one does not assume a safe default when unset).
- **PASS** only if `snapshot_retention_limit` is set to a positive integer.

## Non-compliant example
```hcl
resource "aws_elasticache_cluster" "cache" {
  cluster_id           = "app-cache"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  # snapshot_retention_limit not set (or set to 0) -> FAIL
}
```

## Remediated example
```hcl
resource "aws_elasticache_cluster" "cache" {
  cluster_id              = "app-cache"
  engine                  = "redis"
  node_type               = "cache.t3.micro"
  num_cache_nodes         = 1
  snapshot_retention_limit = 5   # added: retain 5 days of automatic snapshots
}
```

## Remediation steps
1. For every `aws_elasticache_cluster` with `engine = "redis"`, set `snapshot_retention_limit` to a positive number of days (AWS allows up to 35).
2. Optionally set `snapshot_window` to control when the daily snapshot occurs (e.g., during a low-traffic period).
3. Memcached clusters are exempt from this control (Checkov marks them UNKNOWN) since Memcached is a pure, non-persistent cache with no snapshot feature — no action needed there.
4. Note that increasing `snapshot_retention_limit` incurs additional storage cost for retained snapshots.
5. This is a non-disruptive attribute change applied in place; it does not require replacing the cluster.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticCacheAutomaticBackup.py)
- [AWS: Automatic backups for a self-designed cluster in ElastiCache for Redis](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html)
