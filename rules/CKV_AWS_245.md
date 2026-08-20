# CKV_AWS_245: Ensure replicated backups are encrypted at rest using KMS CMKs

## Severity
**LOW** (score: 2.0/10)

Cross-region automated RDS backup replicas can end up stored unencrypted at rest, leaving a full copy of production database contents exposed in a second region outside the source database's encryption guarantees.

## Summary
This check ensures that RDS automated backups replicated to another region (via `aws_db_instance_automated_backups_replication`) are encrypted with a customer-managed KMS key (CMK).

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_db_instance_automated_backups_replication`

## Why it matters
RDS cross-region automated backup replication copies your database snapshots and transaction logs to a secondary AWS region for disaster recovery. If that replicated copy isn't explicitly encrypted with a CMK you control, you either end up with an unencrypted copy of production data sitting in a second region, or with encryption tied to an AWS-managed key which you cannot rotate, audit key usage on, or revoke access to independently. Backups are a favorite target for attackers and a common source of data breaches precisely because they are less actively monitored than the primary database, and a second-region copy multiplies your exposure surface. Using a CMK lets you apply key policies, CloudTrail-log all key usage, and immediately cut off access (by disabling/deleting the key) if the replica region or account is compromised.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` that looks at the `kms_key_id` attribute of the resource, with an expected value of `ANY_VALUE` (i.e., checkov requires the key merely to be set to something, not verifying which specific key).

- **PASS**: `kms_key_id` is set to any non-empty value.
- **FAIL**: `kms_key_id` is absent or empty.

## Non-compliant example
```hcl
resource "aws_db_instance_automated_backups_replication" "example" {
  source_db_instance_arn = aws_db_instance.primary.arn
  # kms_key_id not set -> replica backups will use the default AWS-managed key or fail requirements
}
```

## Remediated example
```hcl
resource "aws_kms_key" "backup_cmk" {
  description         = "CMK for cross-region RDS backup replication"
  enable_key_rotation = true
}

resource "aws_db_instance_automated_backups_replication" "example" {
  source_db_instance_arn = aws_db_instance.primary.arn
  kms_key_id              = aws_kms_key.backup_cmk.arn   # <-- added
}
```

## Remediation steps
1. Create (or identify) a customer-managed KMS key in the destination/replica region — KMS keys are regional, so the CMK must exist in the region the backup is replicated to.
2. Set `kms_key_id` on the `aws_db_instance_automated_backups_replication` resource to that CMK's ARN.
3. Grant the RDS service principal the necessary `kms:Encrypt`/`kms:Decrypt`/`kms:CreateGrant` permissions in the CMK's key policy.
4. Note: the *source* DB instance must already be encrypted (RDS does not support enabling encryption on an existing unencrypted instance in place) — if the source is unencrypted, you must first snapshot, copy with encryption enabled, and restore before replication can be encrypted end-to-end.
5. Enable `aws_kms_key.enable_key_rotation` for ongoing key hygiene.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSInstanceAutoBackupEncryptionWithCMK.py)
- [Terraform: aws_db_instance_automated_backups_replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance_automated_backups_replication)
