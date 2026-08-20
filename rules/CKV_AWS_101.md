# CKV_AWS_101: Ensure Neptune logging is enabled
## Severity
**HIGH** (score: 7.5/10)

Missing Neptune audit logging removes visibility into queries and administrative actions against a graph database that often holds sensitive relationship data, hampering detection of unauthorized access or data theft.

## Summary
This check ensures that Amazon Neptune DB clusters have `audit` CloudWatch log exports enabled so that database access and query activity is captured.

## Applicability
- **CloudFormation**: `AWS::Neptune::DBCluster` resources.
- **Terraform**: `aws_neptune_cluster` resources.

Specifically the `EnableCloudwatchLogsExports`/`enable_cloudwatch_logs_exports` property.

## Why it matters
Neptune audit logs record connection attempts, queries executed (Gremlin/SPARQL/openCypher), and other database-level activity. Without audit logging enabled, there is no forensic trail if the graph database is accessed maliciously, queried for unauthorized data exfiltration, or targeted by an insider threat — incident responders would have no way to reconstruct what data was accessed, by whom, or when. This is also frequently a compliance requirement (PCI-DSS, HIPAA, SOC 2) for any data store holding sensitive information, since audit trails are a foundational control for detection and accountability. Enabling audit log export to CloudWatch also allows integration with automated alerting/SIEM pipelines for real-time anomaly detection.

## How Checkov evaluates this
- **CloudFormation**: checks `Properties.EnableCloudwatchLogsExports`; if the list contains `"audit"`, the check **PASSES**; otherwise **FAILS**.
- **Terraform**: checks the `enable_cloudwatch_logs_exports` attribute; requires that the list contains `"audit"` (checked via `all(elem in ... for elem in ["audit"])`); if present, **PASSES**; if the attribute is missing or doesn't include `"audit"`, **FAILS**.

## Non-compliant example
```hcl
resource "aws_neptune_cluster" "graph" {
  cluster_identifier      = "graph-db"
  engine                  = "neptune"
  skip_final_snapshot     = true
  # No enable_cloudwatch_logs_exports -> audit logging disabled
}
```

## Remediated example
```hcl
resource "aws_neptune_cluster" "graph" {
  cluster_identifier                  = "graph-db"
  engine                              = "neptune"
  skip_final_snapshot                 = true
  enable_cloudwatch_logs_exports = ["audit"]
}
```

## Remediation steps
1. Add `enable_cloudwatch_logs_exports = ["audit"]` (Terraform) or `EnableCloudwatchLogsExports: [audit]` (CloudFormation) to the Neptune cluster definition.
2. Ensure the corresponding Neptune DB cluster parameter group also has `neptune_enable_audit_log` set to `1`, since CloudWatch export alone requires audit logging to be turned on at the parameter-group level to actually populate meaningful data.
3. Set an appropriate CloudWatch Logs retention period for the exported log group to balance cost and compliance retention requirements.
4. Enabling logging can typically be applied without downtime, but verify against your Neptune engine version's maintenance behavior.
5. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NeptuneClusterLogging.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/NeptuneClusterLogging.py)
- [AWS Neptune: Using Neptune audit logs](https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html)
