# CKV_AWS_180: Ensure Image Builder component is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

This only enforces customer-managed KMS keys for Image Builder components rather than checking for encryption itself, so the exposure is limited to reduced key management control over build artifacts.

## Summary
This check requires that an `aws_imagebuilder_component` resource specify a customer-managed KMS key (`kms_key_id`) to encrypt the component's data, instead of relying on the AWS-managed default key.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_imagebuilder_component`
- **Check type:** resource (attribute-value check)

## Why it matters
EC2 Image Builder components define the build/test/validation steps (scripts, packages, configuration) used to produce golden AMIs and container images. These components can embed sensitive logic — internal package repository URLs/credentials, hardening scripts, proprietary configuration, or references to secrets used during the image build. Encrypting components with a customer-managed KMS key ensures your organization controls exactly who (which IAM principals/roles) can decrypt and read that build logic, and lets you audit and revoke access via the key policy and CloudTrail — capabilities not available with the AWS-managed default key. This is particularly important in regulated environments where the AMI build pipeline is part of the software supply chain and unauthorized read access to build components could reveal internal infrastructure details or enable tampering.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `kms_key_id` attribute of `aws_imagebuilder_component`. It expects `ANY_VALUE` — presence of any non-empty value passes; absence of the attribute fails the check.

## Non-compliant example
```hcl
resource "aws_imagebuilder_component" "example" {
  name     = "hardening-component"
  platform = "Linux"
  version  = "1.0.0"
  data     = file("${path.module}/component.yaml")
  # kms_key_id not set -- uses AWS-owned default key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "imagebuilder" {
  description             = "CMK for Image Builder component encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_imagebuilder_component" "example" {
  name       = "hardening-component"
  platform   = "Linux"
  version    = "1.0.0"
  data       = file("${path.module}/component.yaml")
  kms_key_id = aws_kms_key.imagebuilder.arn  # customer managed key
}
```

## Remediation steps
1. Create or select a customer-managed KMS key with a key policy scoped to the roles/users involved in the image build pipeline (Image Builder service role, CI/CD pipeline role, auditors).
2. Set `kms_key_id` on the `aws_imagebuilder_component` resource to the CMK's ARN.
3. Grant the EC2 Image Builder service-linked role and any consuming pipeline roles `kms:Decrypt` and `kms:DescribeKey` permissions via the key policy.
4. Note: changing `kms_key_id` on an existing component typically requires creating a new component version, since components are immutable once created.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ImagebuilderComponentEncryptedWithCMK.py)
- [AWS Image Builder encryption documentation](https://docs.aws.amazon.com/imagebuilder/latest/userguide/security-data-protection.html)
