# CKV_AWS_129: Ensure that respective logs of Amazon Relational Database Service (Amazon RDS) are enabled

## Severity
**LOW** (score: 2.0/10)

Disabled RDS log exports (audit, error, general, slow-query) remove a key detection source for unauthorized database access or abuse, delaying incident response even though the data itself is not directly exposed.

## Summary
This check requires that an RDS instance export at least one log type to CloudWatch Logs via `enabled_cloudwatch_logs_exports`, ensuring database activity and error logs are retained centrally rather than only on the instance itself.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_db_instance`

## Why it matters
Without CloudWatch log export, RDS logs (audit, error, general, slowquery, postgresql upgrade logs, etc., depending on engine) exist only on the ephemeral instance storage and are lost on instance replacement, failover, or deletion. This severely limits incident response and forensics: a database compromise, a SQL-injection attack chain, unauthorized query activity, or a data-exfiltration event may leave no durable, centrally-queryable trail. Centralizing logs to CloudWatch also enables real-time alerting (e.g., CloudWatch Logs metric filters/alarms for failed logins or privilege-escalation queries), supports compliance log-retention requirements (e.g., PCI-DSS, HIPAA), and decouples log retention from the lifecycle of the database instance.

## How Checkov evaluates this
The check (`DBInstanceLogging`, based on `BaseResourceValueCheck`) inspects `enabled_cloudwatch_logs_exports`:
- It reads the `enabled_cloudwatch_logs_exports` list attribute (default `[[]]` if unset).
- **FAIL** if the attribute is missing entirely, or if the first element of the list is empty/falsy (i.e., an empty list `[]`).
- **PASS** if the first element is a non-empty/truthy value (i.e., at least one log type string, such as `"error"` or `"general"`, is present).

In short: at least one log export type must be explicitly configured for the check to pass.

## Non-compliant example
```hcl
resource "aws_db_instance" "app_db" {
  identifier        = "app-db"
  engine            = "mysql"
  engine_version     = "8.0"
  instance_class    = "db.t3.medium"
  allocated_storage = 20
  username          = "admin"
  password          = var.db_password
  # enabled_cloudwatch_logs_exports not set -> FAIL
}
```

## Remediated example
```hcl
resource "aws_db_instance" "app_db" {
  identifier        = "app-db"
  engine            = "mysql"
  engine_version     = "8.0"
  instance_class    = "db.t3.medium"
  allocated_storage = 20
  username          = "admin"
  password          = var.db_password

  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]  # added
}
```

## Remediation steps
1. Determine which log types your database engine supports for CloudWatch export (MySQL: `audit`, `error`, `general`, `slowquery`; PostgreSQL: `postgresql`, `upgrade`; MariaDB: same as MySQL; Oracle: `alert`, `audit`, `trace`, `listener`; SQL Server: `agent`, `error`).
2. Add `enabled_cloudwatch_logs_exports = [...]` with at least one relevant log type to the `aws_db_instance` resource.
3. Ensure the RDS instance's associated parameter group enables the corresponding log outputs (e.g., `general_log = 1`, `slow_query_log = 1` for MySQL) — exporting a log type that the engine isn't actually generating will not produce useful logs.
4. Set a CloudWatch Logs retention policy (`aws_cloudwatch_log_group` with `retention_in_days`) for the exported log groups to control storage cost and meet compliance retention windows.
5. This change is typically applied in place without downtime, though enabling logs may cause a brief RDS instance modification event.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DBInstanceLogging.py)
- [AWS: Publishing Database Logs to Amazon CloudWatch Logs](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html)
