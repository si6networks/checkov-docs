# CKV_AWS_324: Ensure that RDS Cluster log capture is enabled

## Severity
**MEDIUM** (score: 5.0/10)

Without CloudWatch log exports enabled, RDS cluster error and audit-relevant logs are not captured, limiting the ability to detect and investigate suspicious database activity on a sensitive data store.

## Summary
This check ensures RDS clusters (e.g., Aurora) export at least one log type to CloudWatch Logs via `enabled_cloudwatch_logs_exports`, so database activity is captured for audit and troubleshooting.

## Applicability
- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_rds_cluster`

## Why it matters
Database logs (audit, error, general, slow-query logs depending on engine) are essential for detecting and investigating security incidents involving the data tier: brute-force login attempts, SQL injection patterns visible in query logs, unexpected schema changes, privilege escalation via granted roles, or performance anomalies indicative of a denial-of-service or resource-exhaustion attack. Without `enabled_cloudwatch_logs_exports` configured, these logs are either not generated at all or remain only on the DB instance's local storage inaccessible for centralized monitoring, alerting, and long-term retention — meaning a security team investigating a breach months after the fact may find no usable trail. This directly undermines audit and accountability controls (NIST 800-53 AU-2, AU-3, AU-12) and continuous monitoring (CA-7, SI-4(20)).

## How Checkov evaluates this
A `BaseResourceValueCheck` inspecting the first element of `enabled_cloudwatch_logs_exports` with expected value `ANY_VALUE`:
- **PASS** if `enabled_cloudwatch_logs_exports` is set with at least one log type (e.g., `"audit"`, `"error"`, `"general"`, `"slowquery"` for MySQL-compatible Aurora, or `"postgresql"` for Aurora PostgreSQL).
- **FAIL** if the attribute is absent or empty.

## Non-compliant example
```hcl
resource "aws_rds_cluster" "example" {
  cluster_identifier = "example-aurora-cluster"
  engine              = "aurora-mysql"
  engine_version       = "8.0.mysql_aurora.3.04.0"
  master_username      = "admin"
  master_password      = var.db_password
  # No enabled_cloudwatch_logs_exports -> no log capture
}
```

## Remediated example
```hcl
resource "aws_rds_cluster" "example" {
  cluster_identifier             = "example-aurora-cluster"
  engine                          = "aurora-mysql"
  engine_version                   = "8.0.mysql_aurora.3.04.0"
  master_username                  = "admin"
  master_password                  = var.db_password
  enabled_cloudwatch_logs_exports  = ["audit", "error", "general", "slowquery"]  # log capture enabled
}
```

## Remediation steps
1. Add `enabled_cloudwatch_logs_exports` to the `aws_rds_cluster` resource with the log types relevant to the engine (`audit`, `error`, `general`, `slowquery` for Aurora MySQL; `postgresql` for Aurora PostgreSQL).
2. For MySQL-compatible Aurora, enabling the audit log additionally requires setting the `server_audit_logging` and related `server_audit_*` parameters via a custom DB cluster parameter group (`aws_rds_cluster_parameter_group`) — simply listing `"audit"` in `enabled_cloudwatch_logs_exports` is not sufficient on its own for that engine.
3. Set appropriate CloudWatch Logs retention (`aws_cloudwatch_log_group.retention_in_days`) on the auto-created log groups to balance compliance needs against cost.
4. This is generally an in-place modification, applied via `ModifyDBCluster`; no cluster replacement is required, though enabling some log types (like general/slowquery via parameter group changes) may require a reboot of cluster instances to take effect.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSClusterLogging.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_LogAccess.html
