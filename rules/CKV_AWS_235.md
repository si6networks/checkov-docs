# CKV_AWS_235: Ensure that copied AMIs are encrypted

## Severity
**LOW** (score: 2.0/10)

An unencrypted copied AMI leaves the full disk image — potentially including OS files, application code, and embedded credentials or keys — stored at rest in the clear, readable by anyone who gains access to the underlying storage or a shared snapshot.

## Summary
This check ensures that when an Amazon Machine Image (AMI) is copied via `aws_ami_copy`, the resulting copy has its backing EBS snapshots encrypted.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_ami_copy`

## Why it matters
An AMI is backed by one or more EBS snapshots that contain the full disk contents of the source volume(s) — operating system files, installed application code, configuration, and potentially credentials, private keys, or other sensitive data baked into the image. If a copied AMI is left unencrypted, every snapshot and every volume launched from that AMI is stored and transmitted without encryption at rest. This means anyone who gains access to the underlying storage layer (e.g. through an AWS account compromise, an overly permissive snapshot-sharing setting, or a misconfigured backup/DR process that copies snapshots across accounts or regions) can read the full disk image in the clear. Unencrypted AMI copies are also frequently the root cause of accidental data exposure when AMIs are unintentionally shared publicly or with other AWS accounts, since encryption (tied to a KMS key with its own access policy) provides an additional access-control layer beyond the AMI's own permissions.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `encrypted` attribute of the `aws_ami_copy` resource.
- **PASS** if `encrypted = true`.
- **FAIL** if `encrypted` is absent or set to `false`.

## Non-compliant example
```hcl
resource "aws_ami_copy" "backup_copy" {
  name              = "app-ami-dr-copy"
  source_ami_id     = "ami-0123456789abcdef0"
  source_ami_region = "us-east-1"
}
```

## Remediated example
```hcl
resource "aws_ami_copy" "backup_copy" {
  name              = "app-ami-dr-copy"
  source_ami_id     = "ami-0123456789abcdef0"
  source_ami_region = "us-east-1"
  encrypted         = true
}
```

## Remediation steps
1. Add `encrypted = true` to the `aws_ami_copy` resource.
2. If you also want to control which key encrypts the copy (rather than the AWS-managed default EBS key), pair this with a `kms_key_id` (see CKV_AWS_236).
3. Note that changing `encrypted` on an existing `aws_ami_copy` forces resource replacement in Terraform (a new copy must be created, since encryption status cannot be changed on an existing AMI/snapshot) — plan for the copy operation time and update any references (launch templates, Auto Scaling groups) to the new AMI ID once available.
4. If the source AMI is itself unencrypted, AWS will still allow encrypting during the copy operation — this is in fact the standard method used to encrypt a previously unencrypted AMI.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AMICopyIsEncrypted.py)
- [AWS EC2: Copying an AMI (encryption)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/CopyingAMIs.html)
