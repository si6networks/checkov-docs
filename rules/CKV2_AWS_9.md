# CKV2_AWS_9: Ensure that EBS are added in the backup plans of AWS Backup

## Severity
**LOW** (score: 2.0/10)

Unbacked-up EBS volumes risk irreversible data loss after corruption, ransomware, or accidental deletion, an availability/recovery concern rather than a direct confidentiality breach.

## Summary
This check ensures that every `aws_ebs_volume` resource is included in at least one AWS Backup selection, so it is covered by a centrally managed backup plan.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `aws_ebs_volume`, connected via an `aws_backup_selection` resource.

## Why it matters
EBS volumes hold persistent block storage for EC2 instances and are not automatically backed up by AWS — teams must explicitly configure snapshots or an AWS Backup plan. A volume with no backup coverage has no recovery path if it is accidentally deleted, corrupted by a bad deployment, encrypted by ransomware, or lost due to an AZ-level failure. This is especially critical for volumes that are unattached, used for stateful workloads (databases, file servers), or hold data not otherwise replicated elsewhere. AWS Backup centralizes this with policy-driven schedules, retention lifecycle rules, and optional vault lock for tamper-resistant/immutable backups — all of which are bypassed if a volume is never added to a backup selection.

## How Checkov evaluates this
Graph check (`EBSAddedBackup.json`). Logic:
1. Require a **connection** from an `aws_backup_selection` resource to an `aws_ebs_volume` resource (i.e., the selection's `resources` list, or tag-based selection, references the volume).
2. Filter the check's scope to `aws_ebs_volume` resources.

PASS requires the EBS volume to be reachable from at least one `aws_backup_selection`; FAIL if the volume has no such connection.

## Non-compliant example
```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  type              = "gp3"
}
# No aws_backup_selection referencing this volume -> fails
```

## Remediated example
```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  type              = "gp3"

  tags = {
    Backup = "true"
  }
}

resource "aws_backup_vault" "main" {
  name = "ebs-backup-vault"
}

resource "aws_backup_plan" "main" {
  name = "ebs-backup-plan"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 5 * * ? *)"
    lifecycle {
      delete_after = 30
    }
  }
}

resource "aws_backup_selection" "ebs_selection" {
  iam_role_arn = aws_iam_role.backup.arn
  name         = "ebs-volume-selection"
  plan_id      = aws_backup_plan.main.id

  resources = [
    aws_ebs_volume.data.arn
  ]
}
```

## Remediation steps
1. Create (or reuse) an `aws_backup_vault` and `aws_backup_plan` with a schedule and retention lifecycle matching your RPO/RTO requirements.
2. Add an `aws_backup_selection` whose `resources` list includes the EBS volume's ARN, or use `selection_tag` to select all volumes carrying a standard tag (e.g. `Backup = "true"`) so future volumes are automatically included.
3. Attach an IAM role to the selection with the `AWSBackupServiceRolePolicyForBackup` managed policy (or equivalent).
4. For fleets of volumes, tag-based selection scales better than listing individual ARNs — audit tagging conventions to ensure no volume is missed.
5. This is purely additive in Terraform; no volume replacement or downtime is required.
6. Consider AWS Backup Vault Lock for compliance workloads requiring WORM (write-once-read-many) backup immutability.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/EBSAddedBackup.json)
- [AWS Backup: Assigning resources to a backup plan](https://docs.aws.amazon.com/aws-backup/latest/devguide/assigning-resources.html)
