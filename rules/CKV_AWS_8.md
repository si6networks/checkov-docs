# CKV_AWS_8: Ensure all data stored in the Launch configuration or instance Elastic Blocks Store is securely encrypted
## Severity
**LOW** (score: 2.0/10)

Unencrypted EBS volumes on launch configurations/instances expose data at rest, including any sensitive application data, OS artifacts, or credentials stored on disk, to disclosure if the underlying storage or snapshots are ever accessed by an unauthorized party.

## Summary
This check fails when the EBS volumes (root and/or additional block devices) attached to an EC2 instance or Auto Scaling launch configuration are not encrypted.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::AutoScaling::LaunchConfiguration` (CloudFormation), `aws_instance`, `aws_launch_configuration` (Terraform)
- **Check type:** resource

## Why it matters
Unencrypted EBS volumes store all instance disk data — application data, OS files, temp files, swap, logs, and potentially cached credentials or key material — in plaintext at the storage layer. If a volume's underlying snapshot is ever shared incorrectly (a common and frequently-exploited misconfiguration — publicly shared EBS snapshots have led to numerous real-world data exposures), or if physical/logical storage media is compromised or improperly decommissioned, unencrypted data is immediately readable by anyone with access to the snapshot or volume. Since encryption cannot be retroactively enabled on an existing unencrypted volume (it requires creating an encrypted copy), catching this at the IaC review stage — before an instance or ASG launch config goes live — is far cheaper than remediating a fleet of already-running unencrypted volumes later.

## How Checkov evaluates this
- **CloudFormation (`LaunchConfigurationEBSEncryption.py`):** Iterates `Properties.BlockDeviceMappings`; for each mapping with an `Ebs` block, fails if `Ebs.Encrypted` is falsy. If `BlockDeviceMappings` is absent or malformed, result is `UNKNOWN`. Passes only if every EBS block device mapping present has `Encrypted` set truthy.
- **Terraform (`LaunchConfigurationEBSEncryption.py`):** Applies to `aws_launch_configuration` and `aws_instance`.
  - If the `root_block_device` block is missing entirely → **FAIL** (Terraform/AWS creates an unencrypted root volume by default when this block is omitted).
  - Combines `root_block_device` + any `ebs_block_device` blocks and evaluates each with `_is_block_encrypted()`:
    - `encrypted == false` and no `snapshot_id` → **FAIL**.
    - `encrypted == true` → **PASS**.
    - `encrypted` not `true` but a `snapshot_id` is set → **PASS** (assumes the snapshot itself may already be encrypted; Checkov cannot statically verify this).
    - Otherwise → `UNKNOWN`.
  - Overall result is **FAIL** if any block fails, else `UNKNOWN` if any is unknown, else **PASS**.

## Non-compliant example
```hcl
resource "aws_instance" "app" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.medium"
  # root_block_device omitted -> unencrypted root volume by default
}
```

```hcl
resource "aws_launch_configuration" "app_lc" {
  name          = "app-lc"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "t3.medium"

  root_block_device {
    volume_size = 20
    encrypted   = false
  }
}
```

## Remediated example
```hcl
resource "aws_instance" "app" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.medium"

  root_block_device {
    volume_size = 20
    encrypted   = true
    kms_key_id  = aws_kms_key.ebs.arn
  }
}
```

```hcl
resource "aws_launch_configuration" "app_lc" {
  name          = "app-lc"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "t3.medium"

  root_block_device {
    volume_size = 20
    encrypted   = true
  }
}
```

## Remediation steps
1. Explicitly add a `root_block_device` block (Terraform) with `encrypted = true`, even if you don't need to change size/type — omitting the block entirely defaults to unencrypted.
2. For any additional `ebs_block_device` entries, also set `encrypted = true` (or reference an already-encrypted `snapshot_id`).
3. For CloudFormation `AWS::AutoScaling::LaunchConfiguration`, set `Ebs.Encrypted: true` on each entry in `BlockDeviceMappings`.
4. Consider enabling the account/region-level "EBS encryption by default" setting (`aws ec2 enable-ebs-encryption-by-default`) as a safety net so future volumes are encrypted even if IaC omits the setting.
5. Encryption cannot be toggled on an existing volume in place — changing this on a live instance/launch configuration requires replacing the resource (new encrypted volume from a snapshot, or a new instance), so plan for a maintenance window if remediating already-deployed infrastructure.
6. Optionally specify a customer-managed `kms_key_id` for tighter key-policy control instead of the AWS-managed default EBS key.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LaunchConfigurationEBSEncryption.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/LaunchConfigurationEBSEncryption.py)
- [Amazon EBS encryption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)
