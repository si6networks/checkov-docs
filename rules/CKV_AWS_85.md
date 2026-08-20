# CKV_AWS_85: Ensure DocumentDB Logging is enabled
## Severity
**MEDIUM** (score: 5.0/10)

Missing DocumentDB logging limits the ability to detect and investigate unauthorized database access or anomalous query activity after the fact.

## Summary
This check fails when an Amazon DocumentDB cluster does not export `profiler` or `audit` logs to CloudWatch Logs.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::DocDB::DBCluster` (CloudFormation), `aws_docdb_cluster` (Terraform)
- **Check type:** resource

## Why it matters
DocumentDB audit logs record data-definition and data-access events (connections, authentication, and — depending on configuration — authorization and query activity), while profiler logs capture slow-running operations useful for both performance tuning and detecting anomalous query behavior. Without exporting at least one of these log types, there is no external, durable record of who connected to the cluster or what operations were performed against it. This is a significant gap for detecting credential misuse, unauthorized schema/collection changes, or bulk read operations consistent with data exfiltration — especially important for DocumentDB clusters, which frequently store application-critical document data directly accessible via a MongoDB-compatible driver from anywhere with network access and valid credentials.

## How Checkov evaluates this
Both implementations check for at least one of the log types `"profiler"` or `"audit"` in the cluster's CloudWatch log-export configuration:
- **CloudFormation (`DocDBLogging.py`):** Looks at `Properties.EnableCloudwatchLogsExports`. If that value is truthy and contains (as a substring/membership check via `any(elem in logs_exports ...)`) either `"profiler"` or `"audit"`, the check **PASSES**; otherwise **FAILS**.
- **Terraform (`DocDBLogging.py`):** Looks at the `enabled_cloudwatch_logs_exports` attribute (a list). If it's a non-empty list and its first element contains `"profiler"` or `"audit"`, the check **PASSES**; otherwise (attribute absent, empty, or missing both log types) it **FAILS**.

## Non-compliant example
```hcl
resource "aws_docdb_cluster" "app_docs" {
  cluster_identifier  = "app-documents-cluster"
  engine              = "docdb"
  master_username     = "dbadmin"
  master_password     = "ChangeMe123!"
  storage_encrypted   = true
  skip_final_snapshot = true
}
```

## Remediated example
```hcl
resource "aws_docdb_cluster" "app_docs" {
  cluster_identifier              = "app-documents-cluster"
  engine                          = "docdb"
  master_username                 = "dbadmin"
  master_password                 = "ChangeMe123!"
  storage_encrypted                = true
  skip_final_snapshot              = true
  enabled_cloudwatch_logs_exports  = ["audit", "profiler"]
}
```

## Remediation steps
1. Add `enabled_cloudwatch_logs_exports = ["audit", "profiler"]` (Terraform) or `EnableCloudwatchLogsExports: [audit, profiler]` (CloudFormation) to the cluster resource.
2. If enabling `audit` logs, you must also set the cluster parameter group's `audit_logs` parameter to `enabled` — simply exporting the log stream is not sufficient; DocumentDB requires audit logging to be turned on at the parameter-group level as well.
3. Create/verify the target CloudWatch Log Groups exist (AWS creates them automatically on first export in most cases, following the naming convention `/aws/docdb/<cluster-identifier>/<log-type>`).
4. Set an appropriate CloudWatch Logs retention period aligned with your compliance requirements.
5. This is a non-disruptive setting for the cluster itself, but changing the associated cluster parameter group (for audit logging) may require a reboot of cluster instances to take effect, depending on whether the parameter is dynamic or static.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DocDBLogging.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/DocDBLogging.py)
- [Amazon DocumentDB logging](https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html)
