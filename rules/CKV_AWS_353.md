# CKV_AWS_353: Ensure that RDS instances have performance insights enabled
## Severity
**LOW** (score: 2.0/10)

RDS Performance Insights is primarily a query-performance diagnostics feature; its absence hampers operational visibility into database performance rather than closing any direct attack path, so this is chiefly a hygiene/observability recommendation.

## Summary
Requires RDS database instances and Aurora cluster instances to have Performance Insights enabled, with awareness of engine/instance-class combinations where the feature isn't supported.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework**: Terraform
- **Resource types**: `aws_db_instance`, `aws_rds_cluster_instance`

## Why it matters
Performance Insights provides visibility into database load, top SQL statements, wait events, and host-level resource contention — critical both for operational reliability (diagnosing slow queries, capacity issues, lock contention before they cause outages) and for security investigations (unusual query patterns, unexpected load spikes that could indicate data exfiltration via bulk queries, or abuse of a compromised application credential hammering the database). Without Performance Insights enabled, teams typically only have coarse-grained CloudWatch metrics (CPU, connections) and must rely on manual, after-the-fact log analysis — meaning performance degradation and certain classes of abuse can go undiagnosed or undetected for far longer, extending both downtime and potential data-exposure windows.

## How Checkov evaluates this
This is a Terraform resource value check with engine/instance-class carve-outs coded directly into `scan_resource_conf`:
- If `engine` is `"mariadb"` or `"mysql"` **and** `instance_class` is one of the small burstable classes (`db.t2.micro`, `db.t2.small`, `db.t3.micro`, `db.t3.small`, `db.t4g.micro`, `db.t4g.small`), the check returns **UNKNOWN** — Performance Insights isn't available on these smaller instance classes for those engines, so Checkov can't fairly judge it.
- If `engine` is `"db2-se"` or `"db2-ae"` (Amazon RDS for Db2), the check returns **UNKNOWN** — Performance Insights isn't supported for Db2 at all.
- Otherwise, it falls through to the standard value check on `performance_insights_enabled`: **PASS** if `true`, **FAIL** if `false` or unset.

## Non-compliant example
```hcl
resource "aws_db_instance" "app_db" {
  identifier          = "app-db"
  engine              = "postgres"
  engine_version       = "15.4"
  instance_class      = "db.r6g.large"
  allocated_storage   = 100
  username            = "appadmin"
  password            = var.db_password
  skip_final_snapshot = true
  # performance_insights_enabled not set -> defaults to false
}
```

## Remediated example
```hcl
resource "aws_db_instance" "app_db" {
  identifier                      = "app-db"
  engine                          = "postgres"
  engine_version                  = "15.4"
  instance_class                  = "db.r6g.large"
  allocated_storage               = 100
  username                        = "appadmin"
  password                        = var.db_password
  skip_final_snapshot             = true
  performance_insights_enabled    = true
  performance_insights_retention_period = 7
}
```

## Remediation steps
1. Identify all `aws_db_instance` and `aws_rds_cluster_instance` resources.
2. For instance classes/engines that support it, set `performance_insights_enabled = true`.
3. If you're on a small burstable instance class (`db.t2/t3/t4g.micro/small`) with MySQL/MariaDB, or using Db2, this check will correctly report `UNKNOWN` rather than fail — no action is required, but consider upgrading instance class if Performance Insights is operationally important.
4. Set `performance_insights_retention_period` (7 days free tier, or up to 731 days for extended retention) based on your investigation/compliance window needs.
5. Pair with CKV_AWS_354 to ensure Performance Insights data is encrypted with a customer-managed KMS key, since it can capture sensitive query text.
6. Enabling Performance Insights on an existing instance is generally an online operation but may briefly affect I/O; test in a lower environment first for high-throughput production databases.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSInstancePerformanceInsights.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.Overview.Engines.html
