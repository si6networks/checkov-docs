# CKV_AWS_42: Ensure EFS is securely encrypted
## Severity
**LOW** (score: 2.0/10)

An unencrypted EFS file system leaves data at rest exposed to anyone who gains access to the underlying storage or snapshots, a confidentiality gap of moderate severity depending on what the file system stores.

## Summary
This check ensures Amazon EFS (Elastic File System) file systems have encryption at rest enabled.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::EFS::FileSystem` (CloudFormation), `aws_efs_file_system` (Terraform)

## Why it matters
EFS file systems can store sensitive application data, logs, and shared state accessed by multiple EC2 instances, containers, or Lambda functions. Without encryption at rest, data is stored on the underlying physical storage in plaintext, meaning that if the underlying storage media is ever improperly decommissioned, accessed outside normal access controls, or exposed via a misconfigured snapshot/backup/replication path, the data is directly readable. Encryption at rest is also frequently a mandatory control for compliance frameworks (PCI-DSS, HIPAA, SOC 2) and is essentially free from a performance/cost perspective on EFS (AWS-managed KMS keys), making it an easy control to enforce with no operational trade-off.

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck`:
- **CloudFormation:** inspects `Properties/Encrypted` on `AWS::EFS::FileSystem` — **PASS** if `true`, **FAIL** if `false` or absent.
- **Terraform:** inspects the `encrypted` argument on `aws_efs_file_system` — **PASS** if `true`, **FAIL** if `false` or absent (EFS defaults to unencrypted if not specified).

## Non-compliant example
```hcl
resource "aws_efs_file_system" "example" {
  creation_token = "example-fs"
  # encrypted not set -> defaults to false (unencrypted)
}
```

## Remediated example
```hcl
resource "aws_efs_file_system" "example" {
  creation_token = "example-fs"
  encrypted      = true
  kms_key_id     = aws_kms_key.efs.arn  # optional: use a customer-managed key
}
```

## Remediation steps
1. Set `encrypted = true` on the `aws_efs_file_system` resource (or `Properties/Encrypted: true` in CloudFormation).
2. Optionally specify `kms_key_id` to use a customer-managed KMS key instead of the AWS-managed `aws/elasticfs` key, for tighter control over key policy and rotation.
3. **Important:** encryption at rest cannot be enabled on an existing unencrypted EFS file system — this requires creating a new encrypted file system and migrating data (e.g., via AWS DataSync or `rsync`), then cutting over mount targets. Plan for a migration window.
4. Re-run `checkov` to confirm compliance after remediation.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EFSEncryptionEnabled.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/EFSEncryptionEnabled.py)
- [AWS EFS encryption documentation](https://docs.aws.amazon.com/efs/latest/ug/encryption-at-rest.html)
