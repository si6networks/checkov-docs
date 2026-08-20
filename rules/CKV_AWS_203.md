# CKV_AWS_203: Ensure resource is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

An FSx for OpenZFS file system without CMK encryption at rest leaves stored files unprotected against exposure through underlying storage or snapshot access, a moderate-to-significant confidentiality gap depending on data sensitivity.

## Summary
Ensures that an Amazon FSx for OpenZFS file system specifies a customer-managed KMS key (CMK) for encryption, rather than relying on the AWS-managed default key.

## Applicability
- **Terraform**: `aws_fsx_openzfs_file_system` — inspects the `kms_key_id` attribute.

## Why it matters
FSx for OpenZFS file systems store file-level data that is always encrypted at rest by AWS, but by default with the AWS-managed key if no CMK is specified. Relying on the default key means:
- You cannot scope a key policy to restrict which IAM principals/accounts can decrypt the underlying volumes — the AWS-managed key's policy is fixed and shared across the account's usage of that service.
- You lose fine-grained CloudTrail visibility that comes from a dedicated CMK (distinct `kms:Decrypt`/`kms:GenerateDataKey` events tied to a specific key ARN you control), which is often required for security monitoring or compliance evidence.
- You cannot independently disable or schedule deletion of the key to cryptographically revoke access to the file system's data in an emergency, since you don't own the default key.
- Many regulatory frameworks (HIPAA, PCI-DSS, FedRAMP) explicitly require customer-managed keys for data governed by those regimes, not merely "AWS default encryption."

## How Checkov evaluates this
`FSXOpenZFSFileSystemEncryptedWithCMK` is a `BaseResourceValueCheck` expecting `ANY_VALUE` on `kms_key_id`:
- If `kms_key_id` is set to any value → PASS.
- If `kms_key_id` is absent → FAIL (file system still gets AWS-managed-key encryption, but the explicit CMK reference required by this check is missing).

## Non-compliant example
```hcl
resource "aws_fsx_openzfs_file_system" "shared_storage" {
  storage_capacity    = 64
  subnet_ids          = [aws_subnet.private_a.id]
  deployment_type     = "SINGLE_AZ_1"
  throughput_capacity = 64
  # No kms_key_id set -> FAILS CKV_AWS_203 (defaults to AWS-managed key)
}
```

## Remediated example
```hcl
resource "aws_kms_key" "fsx_cmk" {
  description         = "CMK for FSx OpenZFS encryption"
  enable_key_rotation = true
}

resource "aws_fsx_openzfs_file_system" "shared_storage" {
  storage_capacity    = 64
  subnet_ids          = [aws_subnet.private_a.id]
  deployment_type     = "SINGLE_AZ_1"
  throughput_capacity = 64
  kms_key_id          = aws_kms_key.fsx_cmk.arn   # fix
}
```

## Remediation steps
1. Create a dedicated customer-managed KMS key (with rotation enabled) for FSx encryption.
2. Set `kms_key_id` on the `aws_fsx_openzfs_file_system` resource to that CMK's ARN.
3. Grant the FSx service and any consuming principals the necessary `kms:Decrypt`/`kms:GenerateDataKey`/`kms:CreateGrant` permissions in the key policy.
4. Changing `kms_key_id` on an existing file system forces replacement — plan a data migration (backup/restore or DataSync copy) rather than an in-place change, since encryption key changes are not mutable post-creation.
5. Ensure the CMK is available in the same region as the file system.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/FSXOpenZFSFileSystemEncryptedWithCMK.py
- AWS docs: https://docs.aws.amazon.com/fsx/latest/OpenZFSGuide/encryption.html
