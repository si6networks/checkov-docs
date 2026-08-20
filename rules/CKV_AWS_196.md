# CKV_AWS_196: Ensure no aws_elasticache_security_group resources exist
## Severity
**MEDIUM** (score: 5.0/10)

Use of legacy EC2-Classic ElastiCache security groups signals a cluster running outside a VPC, which forfeits fine-grained network segmentation and increases the cache's exposure to broader network access than a VPC security group would allow.

## Summary
Flags any use of the legacy `aws_elasticache_security_group` resource, since ElastiCache Security Groups are a deprecated, EC2-Classic-era construct that should never appear in a modern (VPC-based) Terraform configuration.

## Applicability
- **Terraform**: `aws_elasticache_security_group` — this check unconditionally fails if this resource type is present at all; there is no passing configuration for it.

## Why it matters
ElastiCache Security Groups are only usable for ElastiCache clusters that live outside a VPC (EC2-Classic), which AWS has been retiring for years. Because EC2-Classic networking predates modern VPC network isolation, security groups tied to it:
- Cannot leverage VPC-native network segmentation (subnets, NACLs, security group chaining, VPC endpoints).
- Cannot be used with newer ElastiCache features that require VPC deployment (e.g., encryption in transit/at rest options and certain instance types are VPC-only).
- Signal that the cluster is running in an unsupported/legacy networking mode, which is itself an operational risk since AWS support for EC2-Classic-adjacent resources is being phased out account by account.

Simply having this resource defined — regardless of its rules — indicates the infrastructure is built on a deprecated networking model, which is why Checkov fails it unconditionally rather than inspecting ingress rules.

## How Checkov evaluates this
This is a `BaseResourceCheck` with no conditional logic: `scan_resource_conf()` always returns `CheckResult.FAILED` whenever an `aws_elasticache_security_group` resource block exists in the Terraform configuration, regardless of its contents.

```python
def scan_resource_conf(self, conf):
    # this resource should not exist - ElastiCache Security Groups are for use only
    # when working with an ElastiCache cluster outside of a VPC.
    return CheckResult.FAILED
```

## Non-compliant example
```hcl
resource "aws_elasticache_security_group" "legacy_sg" {
  name                 = "legacy-cache-sg"
  security_group_names = [aws_security_group.legacy_ec2.name]
}
```

## Remediated example
```hcl
resource "aws_security_group" "cache_sg" {
  name   = "cache-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }
}

resource "aws_elasticache_subnet_group" "cache_subnets" {
  name       = "cache-subnets"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

resource "aws_elasticache_cluster" "cache" {
  cluster_id           = "app-cache"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  subnet_group_name    = aws_elasticache_subnet_group.cache_subnets.name
  security_group_ids   = [aws_security_group.cache_sg.id]  # VPC security group instead
}
```

## Remediation steps
1. Remove the `aws_elasticache_security_group` resource entirely.
2. Deploy (or migrate) the ElastiCache cluster into a VPC using `aws_elasticache_subnet_group`.
3. Replace the ElastiCache Security Group with a standard VPC `aws_security_group` and attach it via the cluster's `security_group_ids` argument.
4. If migrating an existing production cluster, note this typically requires creating a new cluster in the VPC and cutting traffic over (in-place EC2-Classic-to-VPC migration for ElastiCache is not supported) — plan for a maintenance window or blue/green cutover.
5. Audit application connection strings/endpoints after migration since VPC-based ElastiCache endpoints and DNS may differ.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticacheHasSecurityGroup.py
- AWS docs: https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/VPCs.html
