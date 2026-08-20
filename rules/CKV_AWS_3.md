# CKV_AWS_3: Ensure all data stored in the EBS is securely encrypted
## Severity
**HIGH** (score: 7.5/10)

This check verifies EBS volume encryption at rest; unencrypted volumes risk exposing sensitive data if a volume, snapshot, or disk image is improperly shared, copied, or accessed outside its intended trust boundary.

## Summary
This check ensures that EBS volumes are created with encryption at rest enabled, checking the `encrypted` attribute in Terraform (`aws_ebs_volume`) or the `Encrypted` property in CloudFormation (`AWS::EC2::Volume`).

## Applicability
- **IaC frameworks:** Terraform, CloudFormation
- **Resource types:** `aws_ebs_volume` (Terraform), `AWS::EC2::Volume` (CloudFormation)

## Why it matters
EBS volumes back EC2 instance root and data disks and can contain application data, databases, logs, temp files with cached secrets, and OS-level artifacts. If a volume is unencrypted, any snapshot taken of it, any copy of that snapshot shared (even accidentally) to another account, or any physical disk/host-level compromise on AWS's infrastructure exposes the raw data without any cryptographic barrier. Encryption at rest also protects against a very common real-world mistake: EBS snapshots being accidentally made public or shared cross-account — an unencrypted public snapshot instantly leaks all its data, whereas an encrypted one still requires the attacker to have access to the KMS key. This check is foundational for compliance frameworks (PCI DSS 3.4, HIPAA, SOC 2 CC6.1) that mandate encryption of data at rest for regulated or sensitive workloads.

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck` checks that look for a boolean-true value:
- **Terraform:** inspects `encrypted` on `aws_ebs_volume`. **PASS** if `encrypted = true`; **FAIL** if absent (AWS default is unencrypted) or `false`.
- **CloudFormation:** inspects `Properties.Encrypted` on `AWS::EC2::Volume`. **PASS** if `Encrypted: true`; **FAIL** if absent or `false`.

## Non-compliant example
```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  # encrypted not set -> defaults to false, check FAILS
}
```

```yaml
Resources:
  DataVolume:
    Type: AWS::EC2::Volume
    Properties:
      AvailabilityZone: us-east-1a
      Size: 100
      # Encrypted not set -> check FAILS
```

## Remediated example
```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true   # encrypt at rest
  kms_key_id        = aws_kms_key.ebs.arn  # optional: use a CMK instead of the AWS-managed default
}
```

```yaml
Resources:
  DataVolume:
    Type: AWS::EC2::Volume
    Properties:
      AvailabilityZone: us-east-1a
      Size: 100
      Encrypted: true   # encrypt at rest
```

## Remediation steps
1. Add `encrypted = true` (Terraform) or `Encrypted: true` (CloudFormation) to every EBS volume resource, including volumes defined inline within `aws_instance.root_block_device` / `ebs_block_device` blocks (note: this specific check targets standalone `aws_ebs_volume`/`AWS::EC2::Volume` resources — inline block devices on instances are covered by related, separate checks).
2. For already-existing unencrypted volumes, encryption cannot be toggled in place — you must snapshot the volume, copy the snapshot with encryption enabled (optionally specifying a CMK), create a new volume from the encrypted snapshot, and swap it in (requires downtime or a maintenance window for attached instances).
3. Consider enabling the account-level "EBS encryption by default" setting (`aws_ebs_encryption_by_default` in Terraform) as a backstop so future volumes are encrypted even if a resource definition omits the attribute.
4. Optionally specify `kms_key_id` to use a customer-managed key for tighter access control instead of the AWS-managed `aws/ebs` key.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/EBSEncryption.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EBSEncryption.py)
