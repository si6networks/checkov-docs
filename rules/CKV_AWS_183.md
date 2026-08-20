# CKV_AWS_183: Ensure EBS Snapshot Copy is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

This verifies use of a customer-managed KMS key for EBS snapshot copies rather than encryption presence, so the impact is reduced control over key access/rotation for already-encrypted backup data.

## Summary
This check requires that an `aws_ebs_snapshot_copy` resource specify a customer-managed KMS key (`kms_key_id`) so the copied snapshot is encrypted with a key your organization controls.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_ebs_snapshot_copy`
- **Check type:** resource (attribute-value check)

## Why it matters
`aws_ebs_snapshot_copy` copies an EBS snapshot, often across regions or accounts for disaster recovery, backup archival, or AMI creation pipelines. If the copy doesn't explicitly specify a CMK, AWS re-encrypts the copy using the AWS-managed default EBS key (or, if the source is unencrypted, may produce an unencrypted copy at all, depending on account defaults). Snapshots frequently contain full disk images with application data, credentials, and configuration files; a copy that loses the customer-managed key protection breaks your organization's ability to centrally govern who can restore volumes from it. This is especially risky for cross-account/cross-region snapshot sharing scenarios, where losing CMK control means you cannot restrict which external principals can decrypt the data even after granting snapshot access.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `kms_key_id` attribute of `aws_ebs_snapshot_copy`. It expects `ANY_VALUE` — any non-empty value passes; if `kms_key_id` is not set, the check FAILS.

## Non-compliant example
```hcl
resource "aws_ebs_snapshot_copy" "example" {
  source_snapshot_id = data.aws_ebs_snapshot.source.id
  source_region       = "us-west-2"
  encrypted           = true
  # kms_key_id not set -- uses AWS-managed default key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "ebs" {
  description             = "CMK for EBS snapshot encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_ebs_snapshot_copy" "example" {
  source_snapshot_id = data.aws_ebs_snapshot.source.id
  source_region       = "us-west-2"
  encrypted           = true
  kms_key_id          = aws_kms_key.ebs.arn  # customer managed key
}
```

## Remediation steps
1. Create or select a customer-managed KMS key in the destination region (KMS keys are regional; you need a CMK available in the copy's target region, or a cross-region grant/replica key).
2. Set `encrypted = true` and `kms_key_id` on the `aws_ebs_snapshot_copy` resource.
3. If copying cross-account, update the CMK's key policy to grant `kms:Decrypt`/`kms:CreateGrant` to the target account's principals, in addition to sharing the snapshot itself.
4. Note: you cannot re-encrypt an existing snapshot copy in place — the `kms_key_id` is fixed at copy time; a change requires deleting and recreating the copy.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EBSSnapshotCopyEncryptedWithCMK.py)
- [AWS EBS encryption documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)
