# CKV_AWS_323: Ensure ElastiCache clusters do not use the default subnet group

## Severity
**MEDIUM** (score: 4.5/10)

Using the default ElastiCache subnet group can place the cluster in a less deliberately controlled network segment, weakening network isolation compared to a purpose-built subnet group.

## Summary
This check ensures ElastiCache clusters explicitly specify a custom `subnet_group_name` rather than relying on the account/region's default subnet group.

## Applicability
- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_elasticache_cluster`

## Why it matters
The default ElastiCache subnet group typically spans the account's default VPC and default subnets, which are often broad, loosely segmented, and shared across many unrelated workloads — with less deliberate network segmentation and security-group scoping than a purpose-built VPC/subnet layout. Placing a cache cluster in the default subnet group means it inherits whatever (often permissive) routing and security posture the default VPC happens to have, rather than being deliberately placed in a private, isolated subnet with tightly scoped security groups and no direct internet route. Since ElastiCache clusters frequently hold sensitive cached data (sessions, PII, tokens) and historically ship with no authentication by default, network-layer isolation is one of the primary controls protecting them — making subnet placement a meaningful security decision, not just a networking detail. This aligns with network segmentation and boundary protection controls (NIST 800-53 SC-7, SC-7(21), AC-4).

## How Checkov evaluates this
A `BaseResourceValueCheck` inspecting `subnet_group_name` with expected value `ANY_VALUE`:
- **PASS** if `subnet_group_name` is explicitly set to any value.
- **FAIL** if the attribute is absent (the cluster then falls back to the implicit default subnet group).

## Non-compliant example
```hcl
resource "aws_elasticache_cluster" "example" {
  cluster_id     = "example-redis"
  engine          = "redis"
  engine_version  = "7.0"
  node_type       = "cache.t3.micro"
  num_cache_nodes = 1
  # No subnet_group_name -> falls back to the account's default subnet group
}
```

## Remediated example
```hcl
resource "aws_elasticache_subnet_group" "example" {
  name       = "example-private-subnets"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

resource "aws_elasticache_cluster" "example" {
  cluster_id         = "example-redis"
  engine              = "redis"
  engine_version       = "7.0"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  subnet_group_name    = aws_elasticache_subnet_group.example.name  # explicit, isolated subnet group
  security_group_ids  = [aws_security_group.redis.id]
}
```

## Remediation steps
1. Create a dedicated `aws_elasticache_subnet_group` referencing private subnets with no direct route to an internet gateway.
2. Set `subnet_group_name` on the `aws_elasticache_cluster` to reference that custom subnet group.
3. Attach a tightly scoped security group (`security_group_ids`) allowing inbound access only from the specific application security groups/CIDRs that need cache connectivity, on the Redis/Memcached port only.
4. Moving an **existing** cluster to a different subnet group requires replacement (ElastiCache does not support in-place subnet group changes for cluster mode disabled clusters) — plan a maintenance window and application reconnect.
5. Verify DNS/endpoint references in application configuration are updated if the cluster is replaced with a new endpoint.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElastiCacheHasCustomSubnet.py
- AWS docs: https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/SubnetGroups.html
