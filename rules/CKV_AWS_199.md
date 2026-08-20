# CKV_AWS_199: Ensure Image Builder Distribution Configuration encrypts AMI's using KMS - a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

AMIs distributed without CMK-based encryption may expose disk contents (which can include application secrets or configuration) to anyone with access to the underlying snapshot, a moderate at-rest confidentiality risk.

## Summary
Ensures that EC2 Image Builder Distribution Configurations encrypt the resulting AMI snapshots with a customer-managed KMS key (CMK) rather than leaving them unencrypted or relying only on the default AWS-managed key.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_imagebuilder_distribution_configuration` — inspects `distribution[0].ami_distribution_configuration[0].kms_key_id`.

## Why it matters
AMIs built through EC2 Image Builder become the "golden images" your fleet launches from, and they typically include your organization's software, agents, configuration, and sometimes baked-in credentials, TLS material, or licensing data. If the resulting AMI's underlying EBS snapshot is unencrypted:
- The snapshot can potentially be shared or copied more permissively without you noticing key-based access control is missing.
- You lose the ability to use KMS key policies/CMK grants as an additional access-control and audit boundary (CloudTrail logs of `kms:Decrypt` calls) for who can actually use/copy the AMI.
- You cannot cryptographically prove separation between environments/accounts sharing the AMI (e.g., dev sharing to prod) since CMK key policies are what actually restrict cross-account AMI usability, not just AMI launch permissions.
- Without a CMK, you rely on the AWS-managed default key, which cannot be scoped with a custom key policy, cannot be rotated on your own schedule, and cannot be revoked/disabled independently to kill access to a specific AMI lineage.

## How Checkov evaluates this
`ImagebuilderDistributionConfigurationEncryptedWithCMK` is a `BaseResourceValueCheck` that inspects the nested attribute path `distribution/[0]/ami_distribution_configuration/[0]/kms_key_id` and expects `ANY_VALUE` (i.e., any non-null value passes):
- If `kms_key_id` is set to any KMS key ARN/ID/alias → PASS.
- If unset/omitted → FAIL.

Note the check does not verify the key is actually a *customer-managed* key (as opposed to accidentally referencing the AWS-managed `alias/aws/ebs` key) — it only verifies that a `kms_key_id` is explicitly specified.

## Non-compliant example
```hcl
resource "aws_imagebuilder_distribution_configuration" "golden_image" {
  name = "golden-image-dist"

  distribution {
    region = "us-east-1"

    ami_distribution_configuration {
      name = "golden-image-{{ imagebuilder:buildDate }}"
      # No kms_key_id set -> FAILS CKV_AWS_199
    }
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "ami_cmk" {
  description             = "CMK for Image Builder AMI encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_imagebuilder_distribution_configuration" "golden_image" {
  name = "golden-image-dist"

  distribution {
    region = "us-east-1"

    ami_distribution_configuration {
      name        = "golden-image-{{ imagebuilder:buildDate }}"
      kms_key_id  = aws_kms_key.ami_cmk.arn   # fix: explicit CMK
    }
  }
}
```

## Remediation steps
1. Create (or identify) a customer-managed KMS key dedicated to AMI/EBS encryption, with key rotation enabled.
2. Set `ami_distribution_configuration.kms_key_id` on each distribution block to that CMK's ARN (do not use the account default `alias/aws/ebs`).
3. Grant the Image Builder service role (and any accounts you distribute the AMI to) `kms:Decrypt`, `kms:DescribeKey`, and `kms:CreateGrant` permissions in the CMK's key policy.
4. If distributing to multiple regions/accounts, ensure the CMK is either a multi-region key or that a comparable CMK exists in every target region/account, since KMS keys are region-scoped.
5. Existing distribution configurations updated with a new `kms_key_id` only affect future builds — previously built AMIs remain encrypted with whatever key was in effect at build time.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ImagebuilderDistributionConfigurationEncryptedWithCMK.py
- AWS docs: https://docs.aws.amazon.com/imagebuilder/latest/userguide/manage-encryption.html
