# CKV_AWS_166: Ensure Backup Vault is encrypted at rest using KMS CMK

## Severity
**MEDIUM** (score: 5.0/10)

An unencrypted-at-rest Backup Vault means that backup data (often a copy of production data) is not protected by a customer-managed key, increasing exposure if the underlying storage is ever accessed outside normal channels.

## Summary
This check requires that AWS Backup Vaults specify a KMS key (a customer managed key, or at minimum any explicit key ARN) used to encrypt the backups stored within them, rather than relying on implicit/default encryption behavior.

## Applicability
- **Terraform**: `aws_backup_vault`
- **CloudFormation**: `AWS::Backup::BackupVault`

## Why it matters
AWS Backup Vaults hold recovery points (backups) for resources like EBS volumes, RDS databases, DynamoDB tables, and EFS file systems — often full copies of production data, including sensitive customer data, credentials embedded in configuration, or regulated data subject to compliance requirements. If a vault does not have an explicit KMS key configured, backups may end up encrypted with a default/AWS-managed key that the organization does not control, cannot rotate on its own schedule, and cannot restrict access to via key policy.

Using a customer-managed KMS key (CMK) lets the organization:
- Control and audit exactly which IAM principals can decrypt (restore) backup data, independent of who has access to the vault itself, via the key policy.
- Rotate or revoke the key to cryptographically render old backups unreadable if needed (e.g. during an incident or offboarding).
- Meet compliance frameworks that require customer-controlled encryption keys for data at rest (e.g. certain PCI-DSS, HIPAA, or contractual requirements).

Without this control, backup data — frequently a rich, consolidated target for attackers because it aggregates data from many resources in one place — may be protected only by default encryption with weaker access-control granularity.

## How Checkov evaluates this
For Terraform, the check inspects the `kms_key_arn` attribute on `aws_backup_vault` and passes if it is set to **any non-empty value** (`ANY_VALUE` sentinel — it does not validate the key is a true CMK versus an AWS managed key, just that a key ARN is explicitly present). If the attribute is absent, the check **FAILS**.

For CloudFormation, it inspects `Properties.EncryptionKeyArn` on `AWS::Backup::BackupVault` with the same "any value" logic — absence of the property causes a **FAIL**.

## Non-compliant example
```hcl
resource "aws_backup_vault" "main" {
  name = "prod-backup-vault"
  # kms_key_arn not set -> vault uses AWS default backup encryption
}
```

## Remediated example
```hcl
resource "aws_kms_key" "backup" {
  description             = "CMK for AWS Backup vault encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_backup_vault" "main" {
  name        = "prod-backup-vault"
  kms_key_arn = aws_kms_key.backup.arn  # added
}
```

## Remediation steps
1. Create (or identify) a customer-managed KMS key dedicated to backup encryption, with `enable_key_rotation = true` and a key policy restricting decrypt/restore permissions to the roles that legitimately need to restore data.
2. Set `kms_key_arn` (Terraform) or `EncryptionKeyArn` (CloudFormation) on the `aws_backup_vault` resource to that key's ARN.
3. Note: `kms_key_arn` can typically only be set at vault **creation** — changing it on an existing vault usually forces resource replacement, and existing recovery points remain encrypted with the original key; plan a migration (new vault + backup plan re-pointed to it) rather than expecting an in-place update.
4. Ensure the AWS Backup service role has `kms:Decrypt`/`kms:GenerateDataKey` permissions on the CMK's key policy, or backups will fail to encrypt/restore.
5. Apply the same treatment to all vaults used by backup plans covering production or regulated data.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/BackupVaultEncrypted.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/BackupVaultEncrypted.py
- AWS docs: https://docs.aws.amazon.com/aws-backup/latest/devguide/encryption.html
