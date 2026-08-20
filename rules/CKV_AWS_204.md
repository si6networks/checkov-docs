# CKV_AWS_204: Ensure AMIs are encrypted using KMS CMKs
## Severity
**LOW** (score: 2.0/10)

Unencrypted AMI EBS block devices expose the disk image's contents, which can include application data or secrets baked into the image, to anyone who can access the underlying snapshot.

## Summary
Ensures that any `aws_ami` resource defining its own EBS block devices (rather than deriving them entirely from a snapshot) has those EBS volumes encrypted, so that the resulting AMI does not produce unencrypted instance storage.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_ami` — inspects each entry in `ebs_block_device` for `snapshot_id` and `encrypted`.

## Why it matters
An AMI's EBS block device mappings determine how instances launched from it are provisioned. If an `ebs_block_device` entry is not derived from an existing (presumably already-encrypted) snapshot and does not set `encrypted = true`, every instance launched from that AMI will get an unencrypted root/data volume by default. This means:
- Data written by any application to that unencrypted volume — logs, temp files, databases, cached secrets — is stored in plaintext on the underlying physical storage medium.
- If the volume/snapshot is ever shared, copied cross-account, or exposed via a misconfigured resource policy, there is no cryptographic barrier protecting its contents — only IAM permissions, which are more prone to misconfiguration.
- This directly undermines organizational "encrypt everything at rest" policies and account-level EBS encryption-by-default settings if the AMI resource explicitly overrides them with unencrypted volumes.

## How Checkov evaluates this
`AMIEncryptionWithCMK` is a `BaseResourceCheck` with custom logic:
1. If `ebs_block_device` is present, iterate over each mapping.
2. For each mapping that does **not** reference an existing `snapshot_id` (i.e., it's a fresh volume, not one derived from an already-encrypted snapshot):
   - If `encrypted` is not set at all → FAIL.
   - If `encrypted` is explicitly `false` → FAIL.
3. If every block device either has a `snapshot_id` or has `encrypted = true` → PASS.
4. If there is no `ebs_block_device` at all → PASS (pass-through; nothing to check, e.g., AMI copies or import-based AMIs).

Note: despite the check's title mentioning "using KMS CMKs," the actual Terraform implementation only verifies the `encrypted` boolean — it does not inspect a specific `kms_key_id`.

## Non-compliant example
```hcl
resource "aws_ami" "custom_image" {
  name                = "custom-app-image"
  virtualization_type = "hvm"
  root_device_name    = "/dev/xvda"

  ebs_block_device {
    device_name = "/dev/xvda"
    volume_size = 20
    # no snapshot_id, encrypted omitted -> FAILS CKV_AWS_204
  }
}
```

## Remediated example
```hcl
resource "aws_ami" "custom_image" {
  name                = "custom-app-image"
  virtualization_type = "hvm"
  root_device_name    = "/dev/xvda"

  ebs_block_device {
    device_name = "/dev/xvda"
    volume_size = 20
    encrypted   = true   # fix
    kms_key_id  = aws_kms_key.ami_cmk.arn
  }
}
```

## Remediation steps
1. For each `ebs_block_device` block lacking a `snapshot_id`, set `encrypted = true`.
2. Specify a customer-managed `kms_key_id` rather than the account default AMI/EBS key, for tighter key-policy-based access control (recommended even though not strictly required by this specific check).
3. If the AMI is derived from an existing (already encrypted) snapshot via `snapshot_id`, this check passes automatically since the snapshot's own encryption state governs the volume.
4. Enable "EBS encryption by default" at the account/region level (`aws_ebs_encryption_by_default`) as a backstop so future volumes/AMIs are encrypted even if a developer omits the attribute.
5. Rebuilding an AMI with encryption enabled requires creating a new AMI (existing unencrypted AMIs cannot be encrypted in place) — plan to re-point Auto Scaling Groups/launch templates to the new AMI ID and deregister the old one after validation.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AMIEncryption.py
- AWS docs: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
