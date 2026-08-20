# CKV_AWS_322: Ensure ElastiCache for Redis cache clusters have auto minor version upgrades enabled

## Severity
**LOW** (score: 2.0/10)

Disabling automatic minor version upgrades leaves the ElastiCache Redis cluster more likely to run on outdated engine versions that are missing security patches over time.

## Summary
This check ensures ElastiCache Redis cache clusters have `auto_minor_version_upgrade` enabled so security and bug-fix patches released in minor engine versions are applied automatically during the maintenance window.

## Applicability
- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_elasticache_cluster` (Redis engine only — Memcached clusters are exempted, see below)

## Why it matters
Minor version releases of the Redis engine frequently include fixes for security vulnerabilities (e.g., Lua scripting sandbox escapes, memory-corruption bugs, protocol-parsing issues) as well as stability fixes. If auto minor version upgrades are disabled, a cluster can remain on a vulnerable minor version indefinitely unless someone manually tracks AWS's Redis security bulletins and schedules the upgrade — which in practice is inconsistently done across large fleets of clusters. This creates a widening window of exposure to publicly known, already-patched vulnerabilities, directly contradicting flaw-remediation and patch-management controls (NIST 800-53 SI-2, SI-2(2), SI-2(4), SI-2(5)). Enabling automatic minor upgrades lets AWS apply these fixes during your maintenance window without requiring manual tracking.

## How Checkov evaluates this
A `BaseResourceValueCheck` with `missing_block_result = CheckResult.PASSED`, inspecting `auto_minor_version_upgrade`:
- If `conf.get("engine") == ["memcached"]`, the check returns **UNKNOWN** immediately (Memcached does not support this setting the same way, so it's neither passed nor failed).
- Otherwise (Redis, or engine unspecified): **PASS** if `auto_minor_version_upgrade` is `true`, or if the attribute is missing entirely (defaults to pass, unlike most value checks). **FAIL** only if it is explicitly set to `false`.

## Non-compliant example
```hcl
resource "aws_elasticache_cluster" "example" {
  cluster_id                  = "example-redis"
  engine                       = "redis"
  engine_version                = "7.0"
  node_type                     = "cache.t3.micro"
  num_cache_nodes                = 1
  auto_minor_version_upgrade   = false     # blocks automatic security patches
}
```

## Remediated example
```hcl
resource "aws_elasticache_cluster" "example" {
  cluster_id                 = "example-redis"
  engine                      = "redis"
  engine_version               = "7.0"
  node_type                    = "cache.t3.micro"
  num_cache_nodes               = 1
  auto_minor_version_upgrade  = true       # applies minor patches during maintenance window
  maintenance_window            = "sun:05:00-sun:06:00"
}
```

## Remediation steps
1. Remove `auto_minor_version_upgrade = false` or set it to `true` (or simply omit it, since the check's default is a pass).
2. Set an explicit `maintenance_window` at a low-traffic time so automatic minor-version upgrades happen predictably and don't surprise on-call staff.
3. Monitor AWS ElastiCache maintenance notifications so upcoming version upgrades are known in advance.
4. This is an in-place attribute change; no cluster replacement required, though an actual minor-version upgrade event itself may cause a brief failover/restart depending on cluster topology (single-node clusters see a short interruption; replicated/cluster-mode clusters fail over with minimal disruption).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticCacheAutomaticMinorUpgrades.py
- AWS docs: https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/VersionManagement.html
