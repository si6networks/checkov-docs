# CKV_AWS_361: Ensure that Neptune DB cluster has automated backups enabled with adequate retention

## Severity
**LOW** (score: 2.0/10)

A short backup retention period mainly threatens recoverability after data loss, corruption, or a destructive/ransomware event rather than directly exposing data or credentials.

## Summary
This check ensures that an Amazon Neptune DB cluster's automated backup retention period is set to at least 7 days, rather than left at the 1-day default.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::Neptune::DBCluster` (property `BackupRetentionPeriod`), `aws_neptune_cluster` (attribute `backup_retention_period`)

## Why it matters
Neptune's automated backups enable point-in-time restore within the configured retention window. Graph databases often back critical relationship/fraud-detection/recommendation data; if the retention period is left at AWS's 1-day default, a bad migration, an accidental bulk delete, or malicious data tampering discovered even a day or two later becomes unrecoverable via automated backup. A 7+ day window gives operational teams a realistic window to detect and roll back problems, and is frequently a baseline expectation in SOC 2 / ISO 27001 backup-and-recovery controls.

## How Checkov evaluates this
Both implementations extend `BaseResourceCheck` with an explicit numeric comparison against the `BackupRetentionPeriod` / `backup_retention_period` field:
- **CloudFormation:** reads `Properties/BackupRetentionPeriod`, defaulting to `1` if absent. **PASSES** only if `>= 7`; otherwise **FAILS**.
- **Terraform:** reads `backup_retention_period`, defaulting to `[1]` if absent. **PASSES** only if `>= 7`; otherwise **FAILS**.

An explicitly configured value below 7 fails identically to an omitted attribute (both fall back to/compare against the 1-day default baseline).

## Non-compliant example
```hcl
resource "aws_neptune_cluster" "graph_db" {
  cluster_identifier      = "example-neptune"
  engine                  = "neptune"
  backup_retention_period = 1
  skip_final_snapshot     = true
}
```

## Remediated example
```hcl
resource "aws_neptune_cluster" "graph_db" {
  cluster_identifier      = "example-neptune"
  engine                  = "neptune"
  backup_retention_period = 7
  skip_final_snapshot     = true
}
```

CloudFormation equivalent:
```yaml
Resources:
  GraphDb:
    Type: AWS::Neptune::DBCluster
    Properties:
      DBClusterIdentifier: example-neptune
      BackupRetentionPeriod: 7
```

## Remediation steps
1. Set `backup_retention_period` (Terraform) or `BackupRetentionPeriod` (CloudFormation) to `7` or higher.
2. This is a mutable cluster property and does not require replacement, though it increases backup storage cost.
3. Pair with `copy_tags_to_snapshot` (see CKV_AWS_362) and consider cross-region snapshot copies for disaster recovery.
4. Verify with `aws neptune describe-db-clusters` after applying.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NeptuneClusterBackupRetention.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/NeptuneClusterBackupRetention.py
- AWS docs: https://docs.aws.amazon.com/neptune/latest/userguide/backup-restore-overview.html
