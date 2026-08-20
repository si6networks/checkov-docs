# CKV_AWS_106: Ensure EBS default encryption is enabled
## Severity
**LOW** (score: 2.0/10)

Leaving EBS default encryption disabled means any new volume created without an explicit encryption setting stores data at rest unencrypted, exposing sensitive data if the underlying storage is ever exposed or improperly decommissioned.

## Summary
This check ensures that EBS encryption-by-default is enabled at the account/region level, so that every new EBS volume is automatically encrypted at rest without relying on developers to remember to set encryption per-volume.

## Applicability
Terraform resource `aws_ebs_encryption_by_default`, an account/region-level singleton setting (via the `enabled` attribute).

## Why it matters
Without account-level EBS encryption-by-default, encryption becomes an opt-in, per-resource decision that depends on every engineer remembering to set `encrypted = true` on every `aws_ebs_volume`/`aws_instance` root/block-device definition. Any volume created without that setting is stored unencrypted, meaning its data-at-rest (including any snapshots taken from it) is not protected by KMS-based encryption — if a snapshot is inadvertently shared, if underlying storage media is retired improperly, or if the account is compromised and volumes/snapshots are exfiltrated, unencrypted data is directly readable. Enabling default encryption removes this human-error risk by making encryption automatic and mandatory for all new EBS volumes and snapshots created in the account/region going forward, which is also a common CIS AWS Foundations Benchmark requirement.

## How Checkov evaluates this
This is a Python check built on `BaseResourceValueCheck`, inspecting the `enabled` attribute of `aws_ebs_encryption_by_default`:
- If the resource is **absent** entirely, the check **PASSES** (`missing_block_result=CheckResult.PASSED`) — this reflects Checkov's default-pass behavior for a missing/undeclared resource rather than a statement about AWS's actual account default (which is disabled unless explicitly turned on).
- If the resource exists and `enabled` is `true` (or omitted, since the argument defaults to `true`), the check **PASSES**.
- If the resource exists and `enabled` is explicitly set to `false`, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_ebs_encryption_by_default" "example" {
  enabled = false
}
```

## Remediated example
```hcl
resource "aws_ebs_encryption_by_default" "example" {
  enabled = true
}
```

## Remediation steps
1. Declare an `aws_ebs_encryption_by_default` resource with `enabled = true` in the account/region's Terraform configuration (only one is needed per region, applied once).
2. Optionally set a customer-managed KMS key as the default via `aws_ebs_default_kms_key`, rather than relying on the AWS-managed default key, for tighter key-management control and audit trail.
3. Note this setting only affects newly created volumes/snapshots going forward — existing unencrypted volumes must be separately re-encrypted (typically via snapshot-copy-with-encryption and volume replacement), which may require downtime or a maintenance window.
4. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EBSDefaultEncryption.py)
- [AWS EBS: Encryption by default documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default)
