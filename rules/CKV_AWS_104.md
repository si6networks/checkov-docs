# CKV_AWS_104: Ensure DocumentDB has audit logs enabled
## Severity
**LOW** (score: 2.0/10)

Disabling DocumentDB audit logging removes the record of data access and administrative operations on the database, undermining detection of unauthorized access to potentially sensitive stored data.

## Summary
This check ensures that Amazon DocumentDB cluster parameter groups enable the `audit_logs` parameter so database access/activity is recorded.

## Applicability
- **CloudFormation**: `AWS::DocDB::DBClusterParameterGroup` resources.
- **Terraform**: `aws_docdb_cluster_parameter_group` resources.

Specifically the `audit_logs` parameter within the parameter group's `Parameters`/`parameter` block.

## Why it matters
DocumentDB (MongoDB-compatible) audit logs record connection events, authentication attempts, authorization checks, and DDL/DML operations against the database. Without audit logging enabled, there is no record of who accessed the database, what queries were executed, or when unauthorized access attempts occurred — making it impossible to detect or investigate data breaches, insider misuse, or exploitation after the fact. Regulatory frameworks that govern sensitive data stores (HIPAA, PCI-DSS, SOC 2) commonly require audit trails as a baseline control, and audit logs are frequently the only forensic evidence available when a database-layer compromise is discovered well after the fact.

## How Checkov evaluates this
- **CloudFormation** (`BaseResourceValueCheck`): inspects `Properties/Parameters/audit_logs`, expecting one of the accepted values `["all", "ddl", "dml_read", "dml_write", "enabled"]`. Any other value (or absence) **FAILS**; a match **PASSES**.
- **Terraform**: iterates each `parameter` block; if an entry's `name` is `audit_logs` and its `value` is one of `("enabled", "ddl", "all")`, the check **PASSES**; if no `audit_logs` parameter is found with an accepted value, the check **FAILS**.

Note there's a slight discrepancy between the two implementations' accepted-value lists (CloudFormation's is broader, including `dml_read`/`dml_write`) — treat `all` or `ddl` as the safest cross-compatible choice.

## Non-compliant example
```hcl
resource "aws_docdb_cluster_parameter_group" "docdb_params" {
  family = "docdb5.0"
  name   = "docdb-cluster-pg"

  parameter {
    name  = "tls"
    value = "enabled"
  }
  # No audit_logs parameter -> audit logging disabled
}
```

## Remediated example
```hcl
resource "aws_docdb_cluster_parameter_group" "docdb_params" {
  family = "docdb5.0"
  name   = "docdb-cluster-pg"

  parameter {
    name  = "tls"
    value = "enabled"
  }

  parameter {
    name  = "audit_logs"
    value = "enabled"
  }
}
```

## Remediation steps
1. Add a `parameter` block with `name = "audit_logs"` and `value = "enabled"` (or `"all"`/`"ddl"` for finer-grained coverage) to the DocumentDB cluster parameter group.
2. Attach this parameter group to the relevant `aws_docdb_cluster` (via its `db_cluster_parameter_group_name` attribute) if not already associated.
3. Configure the cluster to export logs to CloudWatch (`enabled_cloudwatch_logs_exports = ["audit"]` on `aws_docdb_cluster`) so the audit records are actually collected and retained.
4. Applying a parameter group change to an active cluster typically requires a reboot to take effect, depending on whether the parameter is dynamic or static — plan a maintenance window.
5. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DocDBAuditLogs.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/DocDBAuditLogs.py)
- [AWS DocumentDB: Auditing Amazon DocumentDB Events](https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html)
