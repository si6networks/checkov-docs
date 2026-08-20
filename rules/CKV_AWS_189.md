# CKV_AWS_189: Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

The check requires a customer-managed KMS key for EBS volumes rather than checking for encryption at all, so failure reduces key rotation/access control over volume data rather than leaving it unencrypted.

## Summary
This check requires that an `aws_ebs_volume` resource specify a customer-managed KMS key (`kms_key_id`) for encryption instead of the AWS-managed default EBS key.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_ebs_volume`
- **Check type:** resource (attribute-value check)

## Why it matters
EBS volumes back EC2 instance storage — OS disks, application data disks, and database volumes — and are among the most common places sensitive data at rest lives in AWS. If encryption is enabled but no CMK is specified, EBS defaults to the AWS-managed key `alias/aws/ebs`. That default key's policy is controlled by AWS, not your organization, so you cannot restrict decrypt access to a specific set of IAM roles, cannot audit key usage at a granular per-team level, and cannot revoke access instantly by disabling the key — actions security teams need during an incident (e.g., a compromised instance profile) or during offboarding. Using a CMK closes this gap and is typically a required control for volumes hosting regulated data (PCI, HIPAA) or for supporting a "crypto-shredding" data destruction strategy where disabling the key renders all volume snapshots and backups unreadable.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `kms_key_id` attribute of `aws_ebs_volume`. It expects `ANY_VALUE` — any non-empty value passes. If `kms_key_id` is absent, the check FAILS, regardless of whether `encrypted = true` is set (encryption itself is covered by a separate Checkov rule).

## Non-compliant example
```hcl
resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  # kms_key_id not set -- uses AWS-managed default key (alias/aws/ebs)
}
```

## Remediated example
```hcl
resource "aws_kms_key" "ebs" {
  description             = "CMK for EBS volume encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted          = true
  kms_key_id         = aws_kms_key.ebs.arn  # customer managed key
}
```

## Remediation steps
1. Create or select a customer-managed KMS key with a key policy scoped to the EC2 instance profiles/roles that need to mount the volume.
2. Set `encrypted = true` and `kms_key_id` on the `aws_ebs_volume` resource.
3. Consider setting the account/region-level EBS encryption default (`aws ec2 enable-ebs-encryption-by-default` + default KMS key) so all future volumes automatically use the CMK even if `kms_key_id` is omitted elsewhere.
4. Note: the KMS key on an EBS volume is fixed at creation — you cannot change it in place. Migrating an existing volume to a new CMK requires creating a snapshot, copying it with the new CMK (`aws_ebs_snapshot_copy` + `kms_key_id`), and creating a new volume from that snapshot, then reattaching (causing an outage window).
5. Grant the CMK's key policy `kms:CreateGrant`, `kms:Decrypt`, and `kms:DescribeKey` to the EC2 service and relevant instance roles.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EBSVolumeEncryptedWithCMK.py)
- [AWS EBS encryption documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)
