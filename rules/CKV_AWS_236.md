# CKV_AWS_236: Ensure AMI copying uses a CMK

## Severity
**LOW** (score: 2.0/10)

The AMI copy is still encrypted, but relying on the AWS-managed default key instead of a customer-managed key removes granular key-policy control, independent auditing, and revocation ability, weakening defense-in-depth for cross-account/DR sharing scenarios.

## Summary
This check ensures that a copied Amazon Machine Image (`aws_ami_copy`) is encrypted using a customer-managed KMS key (CMK) rather than the AWS-managed default key.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_ami_copy`

## Why it matters
While encrypting an AMI copy at all (see CKV_AWS_235) protects against raw data exposure, using the AWS-managed default EBS key (`aws/ebs`) hands over all key-management controls to AWS defaults: you cannot define a custom key policy restricting which principals may use the key, cannot enable/disable the key independently, cannot control its rotation schedule precisely, cannot audit its usage separately from every other unencrypted-by-default resource in the account, and cannot revoke access to specific snapshots without affecting everything else encrypted with that shared default key. This matters most in cross-account AMI sharing and disaster-recovery scenarios: if you share a copied AMI with another AWS account, the recipient account must also have decrypt permissions on the KMS key backing it — a customer-managed key lets you grant that access narrowly and revocably, whereas the default key's policy is far more permissive and account-wide. A CMK also lets you satisfy compliance requirements that mandate customer control over encryption keys (e.g. "customer-managed keys only" clauses in PCI-DSS/HIPAA-adjacent controls) and enables detailed CloudTrail-based auditing of every decrypt/encrypt operation tied specifically to that AMI's data.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `kms_key_id` attribute of the `aws_ami_copy` resource.
- The expected value is `ANY_VALUE` — meaning the check simply verifies that `kms_key_id` is **set to something** (a specific KMS key ARN/ID), not that it matches a particular key.
- **PASS** if `kms_key_id` is present and non-empty (any customer-supplied key reference).
- **FAIL** if `kms_key_id` is absent — in which case AWS falls back to the default `aws/ebs` AWS-managed key.

## Non-compliant example
```hcl
resource "aws_ami_copy" "backup_copy" {
  name              = "app-ami-dr-copy"
  source_ami_id     = "ami-0123456789abcdef0"
  source_ami_region = "us-east-1"
  encrypted         = true
  # no kms_key_id -> falls back to the AWS-managed default key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "ami_key" {
  description = "CMK for AMI copy encryption"
}

resource "aws_ami_copy" "backup_copy" {
  name              = "app-ami-dr-copy"
  source_ami_id     = "ami-0123456789abcdef0"
  source_ami_region = "us-east-1"
  encrypted         = true
  kms_key_id        = aws_kms_key.ami_key.arn
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key dedicated or scoped appropriately to AMI/EBS encryption.
2. Set `kms_key_id` on the `aws_ami_copy` resource to that key's ARN (or key ID).
3. Ensure `encrypted = true` is also set (required alongside `kms_key_id` — see CKV_AWS_235).
4. Update the CMK's key policy to grant `kms:Decrypt`/`kms:CreateGrant` to any accounts or roles that need to launch instances from this AMI, especially in cross-account sharing scenarios.
5. Changing `kms_key_id` on an existing `aws_ami_copy` forces resource replacement — plan for the AMI copy time and update downstream references (launch templates/ASGs) to the new AMI ID.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AMICopyUsesCMK.py)
- [AWS KMS: Customer managed keys](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk)
