# CKV_AWS_325: Ensure that RDS Cluster audit logging is enabled for MySQL engine
## Severity
**LOW** (score: 2.0/10)

Disabling audit-log export for RDS MySQL/Aurora clusters removes a security-critical detective control, blinding responders to unauthorized queries, privilege abuse, or data exfiltration attempts against the database.

## Summary
This check requires that RDS clusters running a MySQL-compatible engine (Aurora, Aurora-MySQL, or MySQL) export their audit log to CloudWatch Logs via `enabled_cloudwatch_logs_exports`.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_rds_cluster`

## Why it matters
Without audit logging, there is no durable, queryable record of who connected to the database, what statements were executed, what schema/permission changes were made, or when failed authentication attempts occurred. In the event of a suspected compromise, data exfiltration, or insider-threat investigation, responders need this trail to reconstruct what happened. Audit logs are also frequently a compliance requirement (e.g., PCI DSS, HIPAA, NIST 800-53 AU-2/AU-3/AU-12) because they provide non-repudiation and support after-the-fact detection of unauthorized access that preventive controls missed. MySQL/Aurora audit logging captures connection events and DDL/DML activity that the default error log does not.

## How Checkov evaluates this
The check (`RDSClusterAuditLogging.py`) inspects `aws_rds_cluster` resources:
1. If `engine` is set and its value is **not** one of `aurora`, `aurora-mysql`, or `mysql`, the result is `UNKNOWN` (only these MySQL-family engines support easy audit-log export; PostgreSQL-based engines use a different logging mechanism and are out of scope for this check).
2. Otherwise, it looks at `enabled_cloudwatch_logs_exports`. If that list contains the string `"audit"`, the check **PASSES**.
3. If `audit` is not present in the exports list (or the attribute is missing entirely), the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_rds_cluster" "bad_example" {
  cluster_identifier = "app-cluster"
  engine             = "aurora-mysql"
  engine_version     = "8.0.mysql_aurora.3.04.0"
  master_username     = "admin"
  master_password     = var.db_password

  # No audit log export configured
  enabled_cloudwatch_logs_exports = ["error"]
}
```

## Remediated example
```hcl
resource "aws_rds_cluster" "good_example" {
  cluster_identifier = "app-cluster"
  engine             = "aurora-mysql"
  engine_version     = "8.0.mysql_aurora.3.04.0"
  master_username     = "admin"
  master_password     = var.db_password

  # Audit log export added
  enabled_cloudwatch_logs_exports = ["error", "general", "audit"]
}
```

## Remediation steps
1. Add `"audit"` to the `enabled_cloudwatch_logs_exports` list on the `aws_rds_cluster` resource.
2. For Aurora MySQL, ensure the associated DB cluster parameter group has audit logging enabled at the engine level (e.g., set `server_audit_logging = 1` and configure `server_audit_events` via `aws_rds_cluster_parameter_group`) — CloudWatch export alone only ships logs that MySQL is configured to produce.
3. Verify the IAM role/permissions allow RDS to publish to CloudWatch Logs (this is typically handled automatically by AWS but confirm no restrictive SCPs/permission boundaries block it).
4. Consider setting a retention policy on the resulting CloudWatch log group to control storage costs while meeting your log-retention compliance window.
5. This is a non-disruptive change — enabling log exports does not require replacing the cluster, but engine parameter group changes may require a reboot depending on the parameter's apply method (`pending-reboot` vs `immediate`).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSClusterAuditLogging.py)
- [AWS: Publishing Aurora MySQL logs to CloudWatch Logs](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_LogAccess.MySQL.PublishtoCloudWatchLogs.html)
