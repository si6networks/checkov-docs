# CKV_AWS_200: Ensure that Image Recipe EBS Disk are encrypted with CMK
## Severity
**LOW** (score: 2.0/10)

Unencrypted EBS volumes baked into an Image Builder recipe leave disk contents (potentially including credentials or configuration) unprotected at rest for anyone able to access the resulting snapshots or images.

## Summary
Ensures that EC2 Image Builder Image Recipe EBS block device mappings are encrypted, and that a KMS key is explicitly specified, rather than shipping unencrypted or default-key-encrypted volumes in the built image.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_imagebuilder_image_recipe` — inspects each entry in `block_device_mapping[].ebs` for `encrypted` and `kms_key_id`.

## Why it matters
An Image Builder Image Recipe defines the EBS volumes that will be attached (and baked into the resulting AMI) when the golden image is built. If a block device's `ebs` mapping omits encryption, the AMI/snapshot produced from it stores potentially sensitive baked-in data — OS files, installed application code, temporary build artifacts, and sometimes secrets left over from provisioning scripts — as an unencrypted EBS snapshot. Unencrypted snapshots:
- Can be exposed if the snapshot or AMI is accidentally shared publicly or cross-account, since there's no cryptographic barrier — only IAM/resource permissions, which are far easier to misconfigure.
- Cannot be protected by a KMS key policy that restricts which principals/accounts may actually decrypt and use the data, removing an important defense-in-depth layer beyond AMI launch permissions.
- Violate common compliance baselines (CIS AWS Foundations, PCI-DSS) that mandate encryption at rest for all EBS-backed storage, especially for golden images used across an organization.

## How Checkov evaluates this
`ImagebuilderImageRecipeEBSEncrypted` is a `BaseResourceCheck` with custom logic in `scan_resource_conf`:
1. Retrieve `block_device_mapping` (a list) from the resource config; if absent, PASS (nothing to check, e.g., snapshot-derived mapping with no explicit `ebs` block).
2. For each mapping entry that has an `ebs` block:
   - If `ebs.encrypted` is falsy/missing → FAIL.
   - If `ebs.encrypted` is set but `ebs.kms_key_id` is missing → FAIL (encryption must use an explicit CMK, not just the default key).
3. If all `ebs` mappings have both `encrypted = true` and a `kms_key_id` set → PASS.

## Non-compliant example
```hcl
resource "aws_imagebuilder_image_recipe" "golden_recipe" {
  name         = "golden-recipe"
  parent_image = "arn:aws:imagebuilder:us-east-1:aws:image/amazon-linux-2-x86/x.x.x"
  version      = "1.0.0"

  block_device_mapping {
    device_name = "/dev/xvda"

    ebs {
      volume_size = 20
      volume_type = "gp3"
      # encrypted and kms_key_id both omitted -> FAILS CKV_AWS_200
    }
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "recipe_cmk" {
  description         = "CMK for Image Builder recipe EBS encryption"
  enable_key_rotation = true
}

resource "aws_imagebuilder_image_recipe" "golden_recipe" {
  name         = "golden-recipe"
  parent_image = "arn:aws:imagebuilder:us-east-1:aws:image/amazon-linux-2-x86/x.x.x"
  version      = "1.0.0"

  block_device_mapping {
    device_name = "/dev/xvda"

    ebs {
      volume_size = 20
      volume_type = "gp3"
      encrypted   = true                       # fix
      kms_key_id  = aws_kms_key.recipe_cmk.arn  # fix
    }
  }
}
```

## Remediation steps
1. For every `block_device_mapping.ebs` block in the recipe, set `encrypted = true`.
2. Set `kms_key_id` to a customer-managed KMS key ARN (do not rely on the account default `alias/aws/ebs` key) so key policies can independently gate access.
3. Ensure the Image Builder service role and any target accounts/regions that will consume the resulting AMI have `kms:Decrypt`/`kms:CreateGrant` on that CMK.
4. Changing block device encryption on an existing recipe requires creating a new recipe version — Image Builder recipes are immutable once referenced by a pipeline build, so bump the `version` and update the pipeline to use the new recipe.
5. Rebuild the AMI after the change; existing AMIs previously built from the unencrypted recipe remain unencrypted and should be deprecated/deregistered once replacements are validated.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ImagebuilderImageRecipeEBSEncrypted.py
- AWS docs: https://docs.aws.amazon.com/imagebuilder/latest/userguide/manage-encryption.html
