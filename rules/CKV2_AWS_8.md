# CKV2_AWS_8: Ensure that RDS clusters has backup plan of AWS Backup

## Severity
**LOW** (score: 2.0/10)

Missing a backup plan for an RDS cluster threatens data availability and recoverability after ransomware or accidental deletion, but does not directly expose data or grant access.

## Summary
This check ensures that every `aws_rds_cluster` resource is included in at least one AWS Backup selection, so it is covered by a centrally managed backup plan.

## Applicability
- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `aws_rds_cluster`, connected via an `aws_backup_selection` resource.

## Why it matters
RDS clusters (Aurora, Aurora Serverless, etc.) have their own native automated backup/snapshot mechanism, but relying on it alone means backups are managed per-cluster with no centralized retention policy, cross-account/cross-region copy, backup vault lock, or unified audit trail. AWS Backup provides a managed, policy-driven backup plan with lifecycle rules, immutability options (vault lock), and centralized monitoring. A cluster with no `aws_backup_selection` referencing it has no guarantee of being captured by an organization's AWS Backup compliance and disaster-recovery posture — if native automated backups are disabled or misconfigured, or if there's a requirement for backups to live in a separate, tamper-resistant vault, that RDS cluster's data is at risk of being unrecoverable after data loss, corruption, or a ransomware-style attack against the primary account.

## How Checkov evaluates this
Graph check (`RDSClusterHasBackupPlan.json`). Logic:
1. Filter to `aws_rds_cluster` resources.
2. Require that each such resource is **connected** to an `aws_backup_selection` resource (Checkov resolves this connection via Terraform references — e.g., the backup selection's `resources` list or `selection_tag` referencing the cluster's ARN, or via `resources = ["*"]`/tag-based selection that Checkov's graph can trace).

PASS requires an existing connection between the RDS cluster and an `aws_backup_selection`; FAIL if no such connection exists.

## Non-compliant example
```hcl
resource "aws_rds_cluster" "app_db" {
  cluster_identifier = "app-cluster"
  engine             = "aurora-mysql"
  master_username    = "admin"
  master_password    = var.db_password
  skip_final_snapshot = true
}
# No aws_backup_selection referencing this cluster -> fails
```

## Remediated example
```hcl
resource "aws_rds_cluster" "app_db" {
  cluster_identifier  = "app-cluster"
  engine              = "aurora-mysql"
  master_username     = "admin"
  master_password     = var.db_password
  skip_final_snapshot = true
}

resource "aws_backup_vault" "main" {
  name = "app-backup-vault"
}

resource "aws_backup_plan" "main" {
  name = "app-backup-plan"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 5 * * ? *)"
    lifecycle {
      delete_after = 35
    }
  }
}

resource "aws_backup_selection" "rds_selection" {
  iam_role_arn = aws_iam_role.backup.arn
  name         = "rds-cluster-selection"
  plan_id      = aws_backup_plan.main.id

  resources = [
    aws_rds_cluster.app_db.arn
  ]
}
```

## Remediation steps
1. Create (or reuse) an `aws_backup_vault` and `aws_backup_plan` with rules matching your organization's RPO/RTO and retention requirements.
2. Create an `aws_backup_selection` whose `resources` list includes the RDS cluster's ARN (or use `selection_tag` to select by tag if you manage backup scope by tagging convention).
3. Ensure the IAM role used by the backup selection (`iam_role_arn`) has the AWS managed policy `AWSBackupServiceRolePolicyForBackup` (or equivalent least-privilege policy) attached.
4. Consider enabling AWS Backup Vault Lock for compliance-mode immutability against ransomware/accidental deletion.
5. This does not require replacing the RDS cluster — it's purely an additive Terraform resource; no downtime.
6. Verify point-in-time recovery / native automated backups are also still configured appropriately as a defense-in-depth complement, not a replacement.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/RDSClusterHasBackupPlan.json)
- [AWS Backup: Assigning resources to a backup plan](https://docs.aws.amazon.com/aws-backup/latest/devguide/assigning-resources.html)
