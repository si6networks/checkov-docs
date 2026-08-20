# CKV2_AWS_27: Ensure Postgres RDS as aws_rds_cluster has Query Logging enabled
## Severity
**LOW** (score: 2.0/10)

Missing query logging on a Postgres RDS cluster removes an audit trail useful for detecting and investigating suspicious database activity, which is an availability/detective-control gap rather than a direct exposure.

## Summary
This check ensures that an Aurora PostgreSQL RDS cluster (`aws_rds_cluster` with `engine = "aurora-postgresql"`) is attached to a parameter group that configures `log_statement` and `log_min_duration_statement`, so that database queries are actually logged.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_rds_cluster` (engine `aurora-postgresql`), connected `aws_rds_cluster_parameter_group`
- **Check type:** Graph-based connection + attribute check

## Why it matters
Without query logging, a compromised database, a malicious insider, or an application bug that issues destructive/unauthorized SQL statements (e.g., mass deletes, unauthorized `SELECT`s of sensitive data, privilege-escalating DDL) leaves no forensic trail. `log_statement` controls which categories of SQL statements PostgreSQL writes to its log (e.g., `ddl`, `mod`, `all`), and `log_min_duration_statement` captures slow queries that can indicate abuse (e.g., data-exfiltration queries scanning large tables) or performance problems. Many compliance frameworks (PCI DSS, HIPAA, SOC 2) explicitly require database activity logging to support incident response and audit trails. Absent this configuration, a security team investigating a breach involving the database has no way to reconstruct what queries were run, by whom, or when.

## How Checkov evaluates this
This is a graph check (`PostgresRDSHasQueryLoggingEnabled.json`). It requires ALL of the following to be true for the cluster to pass:
1. The resource is of type `aws_rds_cluster`.
2. Its `engine` attribute equals `aurora-postgresql`.
3. A graph connection exists from the `aws_rds_cluster` to an `aws_rds_cluster_parameter_group` (i.e., the cluster's `db_cluster_parameter_group_name` references a parameter group resource in the same configuration).
4. That connected `aws_rds_cluster_parameter_group` has a `parameter.*.name` entry equal to `log_statement`.
5. That connected `aws_rds_cluster_parameter_group` has a `parameter.*.name` entry equal to `log_min_duration_statement`.

If the cluster uses the default (unmanaged) parameter group, has no connected custom parameter group, or the connected parameter group is missing either of those two parameter names, the check fails. Note the check only inspects for the *presence* of these parameter names, not their specific values (e.g., it doesn't verify `log_statement` is set to a non-`none` value) — but in practice omitting the parameter entirely leaves logging at PostgreSQL's default (`none`), so declaring the parameter is meaningful.

## Non-compliant example
```hcl
resource "aws_rds_cluster" "app_db" {
  cluster_identifier = "app-aurora-cluster"
  engine              = "aurora-postgresql"
  engine_version      = "15.4"
  master_username     = "admin"
  master_password     = var.db_password
  # No db_cluster_parameter_group_name set — uses AWS default, no logging
}
```

## Remediated example
```hcl
resource "aws_rds_cluster_parameter_group" "app_db_logging" {
  name   = "app-aurora-logging"
  family = "aurora-postgresql15"

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000" # log statements taking longer than 1s
  }
}

resource "aws_rds_cluster" "app_db" {
  cluster_identifier              = "app-aurora-cluster"
  engine                          = "aurora-postgresql"
  engine_version                  = "15.4"
  master_username                 = "admin"
  master_password                 = var.db_password
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.app_db_logging.name
}
```

## Remediation steps
1. Create an `aws_rds_cluster_parameter_group` with `family` matching your Aurora PostgreSQL engine version.
2. Add a `parameter` block for `log_statement` (values: `none`, `ddl`, `mod`, or `all` — choose `ddl` or `mod` at minimum for security auditing; `all` for full statement logging, mindful of log volume/cost).
3. Add a `parameter` block for `log_min_duration_statement` (in milliseconds; `-1` disables, `0` logs all statement durations, or a positive threshold to log only slow queries).
4. Set `db_cluster_parameter_group_name` on the `aws_rds_cluster` resource to reference the new parameter group.
5. Caveat: some RDS cluster parameters are "static" and require a cluster reboot to take effect; changing the parameter group itself does not require replacement of the cluster, but applying the new parameter values may require a maintenance window/reboot.
6. Ensure logs are routed to CloudWatch Logs (`enabled_cloudwatch_logs_exports = ["postgresql"]` on the cluster) so the captured logs are actually retained and queryable.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/PostgresRDSHasQueryLoggingEnabled.json)
- [AWS Aurora PostgreSQL logging documentation](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_LogAccess.MySQL.PublishtoCloudWatchLogs.html)
