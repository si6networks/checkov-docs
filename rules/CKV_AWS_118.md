# CKV_AWS_118: Ensure that enhanced monitoring is enabled for Amazon RDS instances

## Severity
**LOW** (score: 2.0/10)

Enhanced monitoring provides finer-grained OS-level performance metrics for an RDS instance; its absence hampers operational visibility but is not a security audit-logging control and doesn't expose data or credentials.

## Summary
Fails when an RDS DB instance (or RDS cluster instance) does not have Enhanced Monitoring configured with a valid granularity interval.

## Applicability
- **Terraform**: `aws_db_instance`, `aws_rds_cluster_instance` resources.
- **CloudFormation**: `AWS::RDS::DBInstance` (Enhanced Monitoring is not supported at the `AWS::RDS::DBCluster` level, so that resource type is excluded).

## Why it matters
RDS Enhanced Monitoring collects OS-level metrics (CPU, memory, file system, disk I/O, process list) directly from the hypervisor at up to 1-second granularity, in addition to the coarser CloudWatch metrics gathered from the hypervisor host. Without Enhanced Monitoring:
- Operators lack visibility into OS-level resource contention (e.g. memory pressure, swap usage, specific process CPU consumption) during incidents, making root-cause diagnosis of performance degradation or availability incidents slower and less precise.
- Anomalous processes running on the underlying instance (which could indicate a security issue affecting the OS layer, in the rarer cases where that layer is inspectable) are harder to detect.
- Capacity-planning decisions (right-sizing instance class, storage IOPS) rely on coarser, less timely data.

This is primarily an observability/reliability control that supports faster incident response and better capacity planning, which in turn reduces the duration and impact of availability incidents.

## How Checkov evaluates this
- **Terraform**: Checks the `monitoring_interval` attribute against the list of AWS-valid enhanced monitoring intervals: `[1, 5, 10, 15, 30, 60]` (seconds). Passes only if `monitoring_interval` is set to one of these values. (Note: `0` — meaning disabled — is not in the valid list, so it fails, as does an unset attribute.)
- **CloudFormation**: Checks `Properties/MonitoringInterval` against the same set of values, accepting both integer and string representations (`1, 5, 10, 15, 30, 60` and their string forms).

## Non-compliant example
```hcl
resource "aws_db_instance" "bad" {
  identifier        = "app-db"
  engine            = "postgres"
  engine_version    = "16.3"
  instance_class    = "db.t3.medium"
  allocated_storage = 50
  username          = "admin"
  password          = var.db_password
  monitoring_interval = 0
}
```

## Remediated example
```hcl
resource "aws_iam_role" "rds_monitoring" {
  name               = "rds-enhanced-monitoring-role"
  assume_role_policy = data.aws_iam_policy_document.monitoring_assume.json
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_db_instance" "good" {
  identifier          = "app-db"
  engine              = "postgres"
  engine_version      = "16.3"
  instance_class      = "db.t3.medium"
  allocated_storage   = 50
  username            = "admin"
  password            = var.db_password
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
}
```

## Remediation steps
1. Set `monitoring_interval` to one of the valid values: `1`, `5`, `10`, `15`, `30`, or `60` seconds — lower values give finer granularity at slightly higher monitoring cost/overhead.
2. Create (or reference) an IAM role with the `AmazonRDSEnhancedMonitoringRole` managed policy attached, and set `monitoring_role_arn` on the instance — RDS Enhanced Monitoring will fail to enable without this role.
3. This setting can typically be applied to an existing instance via a modify operation and does not require replacement, though it may cause a brief instance reboot depending on the apply-immediately setting.
4. Review the Enhanced Monitoring metrics in CloudWatch Logs (a dedicated log group `RDSOSMetrics` is created) and consider setting a log retention policy, since these metrics are billed separately and can accumulate storage costs at low intervals.
5. For RDS clusters (Aurora), apply `monitoring_interval` on the `aws_rds_cluster_instance` resources, not the cluster resource itself.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSEnhancedMonitorEnabled.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/RDSEnhancedMonitorEnabled.py
- AWS documentation: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.OS.html
