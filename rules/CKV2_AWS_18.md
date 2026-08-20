# CKV2_AWS_18: Ensure that Elastic File System (Amazon EFS) file systems are added in the backup plans of AWS Backup

## Severity
**LOW** (score: 2.0/10)

EFS file systems excluded from AWS Backup plans risk unrecoverable data loss after accidental deletion, corruption, or a ransomware-style event, impacting data availability and integrity.

## Summary
This check ensures that every `aws_efs_file_system` is included in an AWS Backup plan via an `aws_backup_selection` resource, so it is automatically and regularly backed up.

## Applicability
Terraform (AWS provider). Applies to `aws_efs_file_system` resources, evaluated in connection with `aws_backup_selection` (which itself connects to an `aws_backup_plan`).

## Why it matters
EFS file systems often hold application state, shared configuration, or user-uploaded content that is not otherwise reproducible from source control or object storage. Without a backup plan, the only recovery options after accidental deletion, ransomware/malicious encryption, application-level data corruption, or a botched migration are EFS's own point-in-time recovery limitations — or nothing at all. AWS Backup provides centrally-managed, scheduled, retained backups (with optional cross-region/cross-account copy and vault lock for tamper-resistance), which is a standard requirement in business-continuity and disaster-recovery (BC/DR) programs. An EFS volume with no backup selection is a single point of unrecoverable data loss.

## How Checkov evaluates this
This is a graph-based (JSON) policy that filters on `aws_efs_file_system` resources and requires a connection to exist from an `aws_backup_selection` resource to both an `aws_efs_file_system` and an `aws_backup_plan`. In other words, the EFS file system must be reachable through a backup selection that is itself tied to a backup plan. If no `aws_backup_selection` references the file system (directly, by ARN, or via a matching tag-based selection resolved in the graph), the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_efs_file_system" "app_data" {
  creation_token = "app-data"
  encrypted      = true
}
# No aws_backup_plan / aws_backup_selection covers this file system
```

## Remediated example
```hcl
resource "aws_efs_file_system" "app_data" {
  creation_token = "app-data"
  encrypted      = true
}

resource "aws_backup_vault" "main" {
  name = "main-backup-vault"
}

resource "aws_backup_plan" "main" {
  name = "main-backup-plan"

  rule {
    rule_name         = "daily-backup"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 5 * * ? *)"

    lifecycle {
      delete_after = 35
    }
  }
}

resource "aws_iam_role" "backup_role" {
  name               = "aws-backup-role"
  assume_role_policy = data.aws_iam_policy_document.backup_assume.json
}

resource "aws_backup_selection" "efs_selection" {    # <-- fixed: EFS covered by backup plan
  name         = "efs-backup-selection"
  plan_id      = aws_backup_plan.main.id
  iam_role_arn = aws_iam_role.backup_role.arn

  resources = [
    aws_efs_file_system.app_data.arn,
  ]
}
```

## Remediation steps
1. Create (or reuse) an `aws_backup_vault` and `aws_backup_plan` with a schedule and retention (`lifecycle.delete_after`) appropriate to your RPO/RTO requirements.
2. Create an `aws_backup_selection` that includes the EFS file system's ARN (or a tag-based selection matching it) and references the backup plan.
3. Attach an IAM role to the selection with the AWS-managed `AWSBackupServiceRolePolicyForBackup` policy (or equivalent least-privilege policy).
4. Consider enabling AWS Backup Vault Lock for compliance-grade immutability against accidental or malicious deletion of backups.
5. Periodically test restores from the backup plan — an untested backup is not a verified recovery path.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/EFSAddedBackup.json
