# CKV2_AWS_2: Ensure that only encrypted EBS volumes are attached to EC2 instances

## Severity
**LOW** (score: 2.0/10)

Unencrypted EBS volumes attached to EC2 instances leave data at rest exposed if the underlying storage or a snapshot is improperly accessed, risking disclosure of potentially sensitive application data.

## Summary
This check ensures that any EBS volume that is actually attached to an EC2 instance (via `aws_volume_attachment`) has encryption enabled.

## Applicability
Terraform (AWS provider). Applies to `aws_ebs_volume` resources, evaluated in connection with `aws_volume_attachment` resources.

## Why it matters
Unencrypted EBS volumes store data at rest in plaintext on the underlying physical storage. If an attacker gains access to the storage layer (e.g. through a misconfigured snapshot shared publicly/cross-account, improper decommissioning of physical media, or an internal AWS-side incident), unencrypted data is directly readable, whereas an encrypted volume's data is protected by KMS-managed keys even if the raw disk is exposed. Since this check specifically targets volumes that are *attached to running instances* (i.e., actively holding live application/OS data — databases, application state, logs), these are exactly the volumes most likely to contain sensitive data, making encryption here a high-value, low-cost control (EBS encryption has negligible performance overhead and no functional downside for standard EC2 use).

## How Checkov evaluates this
This is a graph-based (JSON) policy that filters on `aws_ebs_volume` resources and **PASSES** if either:
1. No `aws_volume_attachment` connects to the `aws_ebs_volume` (i.e., the volume isn't attached to anything — out of scope for this check), **or**
2. The `aws_ebs_volume.encrypted` attribute equals `true` **and** an `aws_volume_attachment` is connected to it.

In other words: the check only fails when a volume is BOTH attached to an instance AND `encrypted` is not `true` (i.e., `false` or unset — the Terraform/AWS default for `aws_ebs_volume.encrypted` is `false` unless account-level default encryption is enabled).

## Non-compliant example
```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  # encrypted not set -> defaults to false
}

resource "aws_instance" "app" {
  ami               = "ami-0abcdef1234567890"
  instance_type     = "t3.medium"
  availability_zone = "us-east-1a"
}

resource "aws_volume_attachment" "data_attach" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.app.id
}
```

## Remediated example
```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true   # <-- fixed: encryption enabled
  kms_key_id        = aws_kms_key.ebs.arn
}

resource "aws_instance" "app" {
  ami               = "ami-0abcdef1234567890"
  instance_type     = "t3.medium"
  availability_zone = "us-east-1a"
}

resource "aws_volume_attachment" "data_attach" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.app.id
}
```

## Remediation steps
1. Set `encrypted = true` on every `aws_ebs_volume` that will be attached to an instance.
2. Optionally specify `kms_key_id` to use a customer-managed KMS key instead of the AWS-managed default `aws/ebs` key, for tighter key-policy control and cross-account sharing scenarios.
3. Enable EBS encryption by default at the account/region level (`aws_ebs_encryption_by_default`) so future volumes are encrypted automatically even without explicit `encrypted = true`.
4. For existing unencrypted volumes already in production, note that `encrypted` cannot be changed in place — you must create a new encrypted volume (via snapshot copy with encryption, or `aws ec2 copy-snapshot --encrypted`), then detach the old volume and attach the new one, which requires a maintenance window/downtime for that instance.
5. Also apply the same encryption setting to the root block device (`root_block_device.encrypted`) on `aws_instance`/`aws_launch_template`, which this specific check does not cover.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/EncryptedEBSVolumeOnlyConnectedToEC2s.json
