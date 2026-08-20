# CKV_AWS_212: Ensure DMS replication instance is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

DMS replication instances are encrypted by an AWS-managed key by default, so the missing customer-managed KMS key mainly weakens key-rotation and access-control granularity for data actively being migrated, rather than leaving it fully unencrypted.

## Summary
This check ensures that an AWS Database Migration Service (DMS) replication instance is configured with a customer-managed KMS key (CMK) for encryption at rest, rather than relying on the AWS-managed default key or no key at all.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_dms_replication_instance`

## Why it matters
A DMS replication instance temporarily stores and processes data in transit between source and target databases, including staged/cached replication data, logs, and (depending on configuration) full or partial copies of migrated data — which can include sensitive customer or credential data. While DMS instances are encrypted at rest by default using an AWS-managed key, that default key is entirely controlled by AWS: your organization cannot rotate it on its own schedule, restrict which IAM principals can use it via a custom key policy, enable detailed CloudTrail key-usage auditing, or immediately revoke access by disabling the key in an incident. Using a customer-managed KMS key closes this gap — it lets you enforce least-privilege key policies, get granular audit logs of every encrypt/decrypt call, and support compliance regimes (e.g. PCI-DSS, HIPAA) that require organizational control over encryption keys protecting regulated data.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `kms_key_arn` attribute of `aws_dms_replication_instance`:
- It uses `ANY_VALUE` as the expected value, meaning any non-empty value satisfies the check — Checkov does not validate that the ARN points to a customer-managed (vs. AWS-managed) key specifically, it simply confirms that `kms_key_arn` has been explicitly set.
- If `kms_key_arn` is missing, the check **FAILS** (default missing-block behavior for `BaseResourceValueCheck` is `FAILED` unless overridden, which it is not here).
- If `kms_key_arn` is present with any value, the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_dms_replication_instance" "example" {
  replication_instance_id   = "example-dms-instance"
  replication_instance_class = "dms.t3.medium"
  allocated_storage         = 50
  publicly_accessible       = false
}
```

## Remediated example
```hcl
resource "aws_kms_key" "dms_cmk" {
  description             = "CMK for DMS replication instance encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_dms_replication_instance" "example" {
  replication_instance_id    = "example-dms-instance"
  replication_instance_class = "dms.t3.medium"
  allocated_storage          = 50
  publicly_accessible        = false
  kms_key_arn                = aws_kms_key.dms_cmk.arn
}
```

## Remediation steps
1. Create (or identify an existing) customer-managed KMS key intended for DMS encryption, with a key policy that restricts usage to the DMS service principal and the specific IAM roles/users that need it.
2. Set the `kms_key_arn` attribute on the `aws_dms_replication_instance` resource to that key's ARN.
3. Enable automatic key rotation (`enable_key_rotation = true`) on the CMK for defense-in-depth.
4. Note: `kms_key_arn` cannot be changed after the replication instance is created — switching from the default key to a CMK (or between CMKs) requires replacing the instance (destroy/recreate), which causes replication downtime; plan a migration window.
5. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DMSReplicationInstanceEncryptedWithCMK.py)
- [AWS DMS: Setting an encryption key](https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Introduction.KMS.html)
