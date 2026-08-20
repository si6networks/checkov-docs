# CKV_AWS_381: Make sure that aws_codegurureviewer_repository_association has a CMK

## Severity
**LOW** (score: 2.0/10)

Missing customer-managed KMS encryption for CodeGuru repository associations reduces control over encryption key management for source-code review data, a confidentiality gap rather than exposing the data outright.

## Summary
This check ensures an Amazon CodeGuru Reviewer repository association is encrypted with a customer-managed KMS key (CMK) rather than relying on AWS-owned/default encryption.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_codegurureviewer_repository_association`

## Why it matters
CodeGuru Reviewer analyzes source code repositories, which may include proprietary business logic, embedded configuration, or (in poorly hygienic repos) accidentally committed secrets. Encryption-at-rest for the data CodeGuru stores/processes matters because:

- With AWS-owned keys (the default when no CMK is specified), your organization has no control over the key's lifecycle — you cannot rotate it independently, restrict which principals can use it via a key policy, enable detailed CloudTrail logging of key usage, or revoke access in an incident by disabling/deleting the key.
- A customer-managed KMS key lets you enforce least-privilege key policies, set up CloudTrail-based auditing of every decrypt/encrypt operation, and immediately cut off access (by disabling the key) if the repository association's IAM context is ever compromised.
- For compliance frameworks (SOC 2, HIPAA, PCI-DSS, FedRAMP) that require demonstrable control over encryption keys for regulated code/data, CMK usage is often a hard requirement, not just a best practice.

## How Checkov evaluates this
The check reads `kms_key_details` on the resource. It **PASSES** only if `kms_key_details[0].encryption_option` equals `"CUSTOMER_MANAGED_CMK"`. If `kms_key_details` is absent, or `encryption_option` is missing or set to any other value (e.g., the AWS-owned key default), the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_codegurureviewer_repository_association" "example" {
  repository {
    codecommit {
      name = "example-repo"
    }
  }
  # No kms_key_details block -> defaults to AWS-owned key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "codeguru" {
  description             = "CMK for CodeGuru Reviewer repository association"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_codegurureviewer_repository_association" "example" {
  repository {
    codecommit {
      name = "example-repo"
    }
  }

  kms_key_details {
    encryption_option = "CUSTOMER_MANAGED_CMK"
    kms_key_id        = aws_kms_key.codeguru.arn
  }
}
```

## Remediation steps
1. Create (or reuse) a KMS key dedicated to CodeGuru Reviewer, with `enable_key_rotation = true` for automatic annual key rotation.
2. Add a `kms_key_details` block to the repository association with `encryption_option = "CUSTOMER_MANAGED_CMK"` and `kms_key_id` set to the CMK's ARN or ID.
3. Attach a key policy restricting `kms:Decrypt`/`kms:GenerateDataKey` to the CodeGuru Reviewer service principal and the specific IAM roles that need it.
4. Note: changing encryption settings on an existing repository association after creation may require disassociating and re-associating the repository, since KMS configuration is typically set at creation time — check current provider behavior and plan for a brief re-association window.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AWSCodeGuruHasCMK.py)
- [Amazon CodeGuru Reviewer encryption documentation](https://docs.aws.amazon.com/codeguru/latest/reviewer-ug/encryption-at-rest.html)
