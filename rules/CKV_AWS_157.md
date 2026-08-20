# CKV_AWS_157: Ensure that RDS instances have Multi-AZ enabled
## Severity
**LOW** (score: 2.0/10)

Multi-AZ is a high-availability/failover control for RDS, improving resilience against an AZ outage or primary-instance failure, but it has no direct bearing on data confidentiality or access control.

## Summary
This check verifies that a non-Aurora RDS instance has Multi-AZ deployment enabled, so a synchronously-replicated standby exists in a second Availability Zone for automatic failover.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

Terraform (`aws_db_instance`) and CloudFormation (`AWS::RDS::DBInstance`). Aurora engines are automatically excluded (see below), since Aurora storage is inherently replicated across AZs independent of the `MultiAZ` flag.

## Why it matters
A single-AZ RDS instance is a single point of failure at the infrastructure level: if the underlying host fails, the AZ experiences an outage, or scheduled maintenance requires a restart, the database becomes unavailable until AWS (or an operator) recovers it — with no automatic failover target. Multi-AZ deployments maintain a synchronous standby replica in a different AZ; AWS automatically fails over to the standby (typically within 60-120 seconds) during an AZ failure, host failure, storage failure, or even routine maintenance, with no data loss for synchronously committed transactions. Without Multi-AZ, an outage that would otherwise be a brief automated failover becomes a full incident requiring manual point-in-time restore or waiting on AWS's own host-replacement process — this is a core availability/reliability control, not merely encryption or access-control hygiene, but it also has security relevance: it prevents "denial of availability" events (whether from infrastructure failure or e.g. a poorly-timed patch) from becoming a prolonged outage that an attacker or a coincidental external event could otherwise exploit.

## How Checkov evaluates this
Both language checks first inspect the `Engine`/engine attribute: if it contains `"aurora"`, the check returns `UNKNOWN` (not applicable — Aurora doesn't use the `MultiAZ` flag for its replication model). For non-Aurora engines, it falls through to `BaseResourceValueCheck` on `MultiAZ` (CloudFormation `Properties.MultiAZ`) / `multi_az` (Terraform): `PASSED` if `true`, `FAILED` if `false` or unset.

## Non-compliant example
```hcl
resource "aws_db_instance" "orders" {
  identifier        = "orders-db"
  engine            = "postgres"
  engine_version     = "15.4"
  instance_class     = "db.r6g.large"
  allocated_storage  = 100
  username           = "app"
  password           = var.db_password
  # multi_az not set -> defaults to false, single-AZ
}
```

## Remediated example
```hcl
resource "aws_db_instance" "orders" {
  identifier        = "orders-db"
  engine            = "postgres"
  engine_version     = "15.4"
  instance_class     = "db.r6g.large"
  allocated_storage  = 100
  username           = "app"
  password           = var.db_password
  multi_az           = true # <-- added
}
```

## Remediation steps
1. Set `multi_az = true` (Terraform) or `MultiAZ: true` (CloudFormation) on the `aws_db_instance`/`AWS::RDS::DBInstance` resource.
2. Expect roughly double the storage/compute cost for the standby replica — factor this into budget planning.
3. Enabling Multi-AZ on an existing instance triggers an online conversion (no downtime in most cases) but can take significant time for large databases; schedule during a low-traffic window regardless.
4. For Aurora clusters, this check does not apply (`UNKNOWN`) — instead ensure you have at least one reader instance in a different AZ from the writer for equivalent HA.
5. Combine with automated backups, `deletion_protection = true`, and proper `backup_retention_period` for a complete resilience posture.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSMultiAZEnabled.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/RDSMultiAZEnabled.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html
