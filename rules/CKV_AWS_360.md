# CKV_AWS_360: Ensure DocumentDB has an adequate backup retention period

## Severity
**LOW** (score: 2.0/10)

An overly short backup retention window is primarily an availability/recoverability gap (data loss risk from destructive actions or ransomware going undetected past the retention window) rather than a direct confidentiality or access-control exposure.

## Summary
This check ensures that an Amazon DocumentDB cluster's automated backup retention period is set to at least 7 days, rather than left at the 1-day default or configured with an insufficient window.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::DocDB::DBCluster` (property `BackupRetentionPeriod`), `aws_docdb_cluster` (attribute `backup_retention_period`)

## Why it matters
DocumentDB's automated backups provide point-in-time recovery (PITR) for the retention window configured. If the retention period is too short (the AWS default is only 1 day), you have a very narrow window to recover from accidental data deletion, corruption from a bad application deploy, or a ransomware/destructive-attack scenario before the recovery point ages out and is no longer restorable. A short retention window effectively removes your recovery safety net for anything discovered more than a day after the fact — which is common, since data corruption or unauthorized changes are frequently not noticed immediately. A 7+ day window aligns with common compliance baselines and gives operations teams a realistic detection-to-recovery timeframe.

## How Checkov evaluates this
Both implementations extend `BaseResourceValueCheck` but override `scan_resource_conf` with an explicit numeric comparison:
- **CloudFormation:** reads `Properties/BackupRetentionPeriod`, defaulting to `1` if absent. **PASSES** only if the value is `>= 7`; otherwise **FAILS**.
- **Terraform:** reads `backup_retention_period`, defaulting to `[1]` if absent (Terraform values arrive as single-element lists in this framework). **PASSES** only if the value is `>= 7`; otherwise **FAILS**.

Note that an explicitly-set retention period below 7 (e.g. `3`) fails just as much as an entirely omitted attribute, since the omitted case is treated as the AWS default of 1 day.

## Non-compliant example
```hcl
resource "aws_docdb_cluster" "orders_db" {
  cluster_identifier      = "orders-docdb"
  engine                  = "docdb"
  master_username         = "admin"
  master_password         = var.docdb_password
  backup_retention_period = 3
  skip_final_snapshot     = true
}
```

## Remediated example
```hcl
resource "aws_docdb_cluster" "orders_db" {
  cluster_identifier      = "orders-docdb"
  engine                  = "docdb"
  master_username         = "admin"
  master_password         = var.docdb_password
  backup_retention_period = 7
  skip_final_snapshot     = true
}
```

CloudFormation equivalent:
```yaml
Resources:
  OrdersDocDB:
    Type: AWS::DocDB::DBCluster
    Properties:
      MasterUsername: admin
      MasterUserPassword: !Ref DocDBPassword
      BackupRetentionPeriod: 7
```

## Remediation steps
1. Set `backup_retention_period` (Terraform) or `BackupRetentionPeriod` (CloudFormation) to `7` or higher — align with your organization's RPO/compliance requirements (some regimes require 30+ days).
2. This is a mutable property; applying it does not require replacing the cluster, though longer retention incurs additional backup storage cost.
3. Combine with `copy_tags_to_snapshot` and cross-region/cross-account snapshot copying for defense-in-depth against regional failures or account compromise.
4. Verify the change with `aws docdb describe-db-clusters` after apply.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DocDBBackupRetention.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/DocDBBackupRetention.py
- AWS docs: https://docs.aws.amazon.com/documentdb/latest/developerguide/backup_restore.html
