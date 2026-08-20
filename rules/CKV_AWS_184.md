# CKV_AWS_184: Ensure resource is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

The check requires a customer-managed KMS key for EFS rather than checking for encryption itself, so failing it means weaker key governance over file system data rather than unencrypted storage.

## Summary
This check requires that an `aws_efs_file_system` resource specify a customer-managed KMS key (`kms_key_id`) for at-rest encryption instead of the AWS-managed default EFS key.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_efs_file_system`
- **Check type:** resource (attribute-value check)

## Why it matters
Amazon EFS file systems commonly hold shared application data, container persistent volumes (via EKS/ECS), and user file shares. When encryption is enabled without specifying a key, EFS defaults to the AWS-managed key `aws/elasticfilesystem`, which your organization cannot govern via a custom key policy. Using a customer-managed key allows fine-grained control over which IAM principals can mount/decrypt the file system's data, independent audit trails of key usage via CloudTrail, and the ability to immediately disable access by disabling the key — none of which are possible with the default key. This is a standard control expected in regulated environments (HIPAA, PCI-DSS) where the data owner, not the cloud provider, must attest to who can access encryption keys protecting sensitive file shares.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `kms_key_id` attribute of `aws_efs_file_system`. It expects `ANY_VALUE` — any non-empty value passes; the check FAILS if `kms_key_id` is absent (note: this check does not separately validate `encrypted = true`; if encryption is entirely disabled, this specific rule about which key is used is moot, though other Checkov rules cover the encrypted flag).

## Non-compliant example
```hcl
resource "aws_efs_file_system" "example" {
  creation_token = "app-data"
  encrypted      = true
  # kms_key_id not set -- uses AWS-managed default key (aws/elasticfilesystem)
}
```

## Remediated example
```hcl
resource "aws_kms_key" "efs" {
  description             = "CMK for EFS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_efs_file_system" "example" {
  creation_token = "app-data"
  encrypted       = true
  kms_key_id      = aws_kms_key.efs.arn  # customer managed key
}
```

## Remediation steps
1. Create or select a customer-managed KMS key with a key policy restricted to the EFS mount targets' IAM roles/principals (e.g., ECS task roles, EKS node/service account roles).
2. Set `encrypted = true` and `kms_key_id` on the `aws_efs_file_system` resource.
3. Enable key rotation on the CMK.
4. Note: the KMS key used for an EFS file system is set at creation and **cannot be changed afterward** — retrofitting an existing file system requires creating a new encrypted file system with the CMK and migrating data (e.g., via AWS DataSync or manual copy), then repointing mount targets.
5. Ensure the CMK's key policy grants `kms:Decrypt`, `kms:GenerateDataKeyWithoutPlaintext`, and `kms:CreateGrant` to the EFS service.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EFSFileSystemEncryptedWithCMK.py)
- [AWS EFS encryption at rest documentation](https://docs.aws.amazon.com/efs/latest/ug/encryption-at-rest.html)
