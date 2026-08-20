# CKV2_AWS_30: Ensure Postgres RDS as aws_db_instance has Query Logging enabled
## Severity
**LOW** (score: 2.0/10)

Missing query logging on a Postgres RDS instance removes an audit trail useful for detecting and investigating suspicious database activity, a detective-control gap rather than a direct exposure.

## Summary
This check ensures a standalone (non-Aurora) PostgreSQL RDS instance (`aws_db_instance` with `engine = "postgres"`) is attached to a DB parameter group that configures `log_statement` and `log_min_duration_statement`, enabling query logging.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_db_instance` (engine `postgres`), connected `aws_db_parameter_group`
- **Check type:** Graph-based connection + attribute check

## Why it matters
Without statement logging, a PostgreSQL RDS instance offers no audit trail of the queries executed against it. If an attacker gains database credentials (via a leaked secret, SQL injection, or compromised application server), there is no record of what data they accessed, modified, or exfiltrated, which severely hampers incident response and makes it impossible to satisfy audit/compliance requirements (PCI DSS, HIPAA, SOC 2) that mandate logging of data access. `log_statement` controls which statement categories get logged (`ddl`, `mod`, `all`), and `log_min_duration_statement` captures long-running queries that may indicate abuse such as bulk data scraping or a poorly-secured reporting query exposing more data than intended. This check is the non-Aurora counterpart to CKV2_AWS_27, applying the same requirement to classic `aws_db_instance` Postgres deployments.

## How Checkov evaluates this
This is a graph check (`PostgresDBHasQueryLoggingEnabled.json`). Structurally it is defined as an `or` of filter/attribute/connection clauses, but functionally Checkov's graph-check engine treats these clauses as required conditions collectively narrowing to `aws_db_instance` resources with `engine = "postgres"` that have a connected `aws_db_parameter_group` containing both a `log_statement` parameter and a `log_min_duration_statement` parameter. In practice:
1. The resource must be `aws_db_instance`.
2. Its `engine` attribute must be `postgres`.
3. It must be connected to an `aws_db_parameter_group` (via `parameter_group_name`).
4. That parameter group must define a parameter named `log_statement`.
5. That parameter group must define a parameter named `log_min_duration_statement`.

An instance using the AWS default parameter group, or a custom group missing either parameter, fails.

## Non-compliant example
```hcl
resource "aws_db_instance" "app_db" {
  identifier        = "app-postgres"
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = "db.t3.medium"
  allocated_storage = 20
  username          = "admin"
  password          = var.db_password
  # No parameter_group_name — uses AWS default, logging disabled
}
```

## Remediated example
```hcl
resource "aws_db_parameter_group" "app_db_logging" {
  name   = "app-postgres-logging"
  family = "postgres15"

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
}

resource "aws_db_instance" "app_db" {
  identifier          = "app-postgres"
  engine              = "postgres"
  engine_version      = "15.4"
  instance_class      = "db.t3.medium"
  allocated_storage   = 20
  username            = "admin"
  password            = var.db_password
  parameter_group_name = aws_db_parameter_group.app_db_logging.name
}
```

## Remediation steps
1. Create an `aws_db_parameter_group` with `family` matching the PostgreSQL major version in use.
2. Add a `parameter` block for `log_statement` (`ddl`, `mod`, or `all`, as appropriate for your logging/compliance needs).
3. Add a `parameter` block for `log_min_duration_statement` (milliseconds; use a positive threshold to focus on slow/expensive queries, or `0` to log every statement's duration).
4. Set `parameter_group_name` on the `aws_db_instance` to reference the new group.
5. Enable `enabled_cloudwatch_logs_exports = ["postgresql"]` so logs are shipped to CloudWatch Logs for retention and alerting, rather than only living on the instance's local log files.
6. Caveat: changing certain parameters requires a "pending-reboot" apply for static parameters; plan a maintenance window since some settings only take effect after a DB instance reboot.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/PostgresDBHasQueryLoggingEnabled.json)
- [AWS RDS PostgreSQL logging documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.Concepts.PostgreSQL.html)
