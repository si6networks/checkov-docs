# CKV2_AWS_50: Ensure AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to enabled
## Severity
**LOW** (score: 2.0/10)

Disabling Multi-AZ automatic failover on an ElastiCache Redis replication group is an availability/resilience gap rather than a confidentiality or integrity risk.

## Summary
This check fails when an `aws_elasticache_replication_group` (Redis) does not have `automatic_failover_enabled` set to `true`, leaving the cluster without automatic promotion of a replica to primary if the primary node fails.

## Applicability
- **IaC framework:** Terraform
- **Resource/entity types:** `aws_elasticache_replication_group`

## Why it matters
Without automatic failover, if the primary node in a Redis replication group fails (hardware failure, AZ outage, node reboot for maintenance), there is no automatic promotion of a read replica to primary — the cluster experiences a write outage until an operator manually intervenes to promote a replica or ElastiCache completes a slower, non-Multi-AZ recovery. For any workload using ElastiCache as a session store, cache, rate-limiter, or queue for latency-sensitive paths, this can mean an extended availability incident precisely at the moment of underlying infrastructure failure — the scenario automatic failover exists to handle. Multi-AZ with automatic failover also protects against a single-AZ outage taking down the entire cache tier, since replicas can be (and should be) placed in different Availability Zones from the primary.

## How Checkov evaluates this
This is a graph-based JSON policy checking a single attribute:
- **Attribute checked:** `automatic_failover_enabled` on `aws_elasticache_replication_group`
- **Operator:** `equals`, value `"true"`
- **PASS** only if explicitly set to `true`.
- **FAIL** if set to `false` or left unset (Terraform's default is `false` for this argument).
- Note: `automatic_failover_enabled = true` also requires at least one replica (`num_cache_clusters >= 2` or `replicas_per_node_group >= 1` when using `num_node_groups`), and is unsupported on `cache.t1.*`/some `cache.t2.*` node types — the check does not itself validate these prerequisites, so setting the flag on an incompatible topology will fail at apply/plan time rather than at the Checkov scan.

## Non-compliant example
```hcl
resource "aws_elasticache_replication_group" "bad" {
  replication_group_id = "app-cache"
  description           = "Application cache"
  node_type             = "cache.m6g.large"
  num_cache_clusters    = 2
  engine                = "redis"
  engine_version        = "7.0"
  automatic_failover_enabled = false
}
```

## Remediated example
```hcl
resource "aws_elasticache_replication_group" "good" {
  replication_group_id       = "app-cache"
  description                = "Application cache"
  node_type                  = "cache.m6g.large"
  num_cache_clusters         = 2
  engine                     = "redis"
  engine_version             = "7.0"
  automatic_failover_enabled = true
  multi_az_enabled           = true
}
```

## Remediation steps
1. Set `automatic_failover_enabled = true`.
2. Ensure at least 2 cache clusters/nodes exist (`num_cache_clusters >= 2`, or configure `num_node_groups`/`replicas_per_node_group` for a sharded cluster-mode-enabled setup) so there is a replica available to promote.
3. Also enable `multi_az_enabled = true` so replicas are automatically placed across distinct Availability Zones for true resilience against an AZ-level failure.
4. Confirm the chosen `node_type` supports automatic failover (most current-generation node types do; older `cache.t1`/some `cache.t2` types do not).
5. Enabling this on an existing single-node replication group typically requires adding a replica first; depending on current topology this may involve a brief failover event — schedule during a maintenance window.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/ElastiCacheRedisConfiguredAutomaticFailOver.json
- AWS docs: https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html
