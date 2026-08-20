# CKV_AWS_262: Ensure Kendra index Server side encryption uses CMK

## Severity
**LOW** (score: 2.0/10)

Kendra indexes are already encrypted at rest by default even without a CMK, so the gap here is losing customer-controlled key policy, rotation, and decrypt-level audit trail over enterprise search content rather than leaving the data unencrypted outright.

## Summary
This check ensures that an Amazon Kendra index's server-side encryption configuration specifies a KMS key ID, rather than relying on AWS's default (unspecified/AWS-owned) encryption.

## Applicability
- **Terraform**: resource `aws_kendra_index`

## Why it matters
Amazon Kendra indexes ingest and store enterprise search content, which often includes internal documents, wikis, support tickets, and other business-sensitive data — exactly the kind of content organizations want indexed for a search experience, and exactly the kind of content that shouldn't be broadly readable if the underlying storage is compromised. Encrypting with a customer-managed key (CMK) rather than depending purely on default encryption gives you control over key policies (who can use the key to decrypt), key rotation, cross-account access boundaries, and CloudTrail visibility into every decrypt operation. Without a CMK, key management defaults to AWS-owned keys that the customer cannot audit, restrict, or revoke independently of the AWS account itself.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that looks for any non-empty value at the nested attribute path `server_side_encryption_configuration/[0]/kms_key_id`:
- **PASS**: the `server_side_encryption_configuration` block is present and its `kms_key_id` is set to any value.
- **FAIL**: the block is missing, or present without a `kms_key_id`.

## Non-compliant example
```hcl
resource "aws_kendra_index" "search" {
  name     = "enterprise-search"
  role_arn = aws_iam_role.kendra.arn
  edition  = "DEVELOPER_EDITION"
  # no server_side_encryption_configuration block
}
```

## Remediated example
```hcl
resource "aws_kendra_index" "search" {
  name     = "enterprise-search"
  role_arn = aws_iam_role.kendra.arn
  edition  = "DEVELOPER_EDITION"

  server_side_encryption_configuration {
    kms_key_id = aws_kms_key.kendra.arn
  }
}

resource "aws_kms_key" "kendra" {
  description         = "CMK for Kendra index encryption"
  enable_key_rotation = true
}
```

## Remediation steps
1. Create (or identify) a customer-managed KMS key dedicated to Kendra index encryption, with `enable_key_rotation = true`.
2. Add a `server_side_encryption_configuration { kms_key_id = ... }` block to the `aws_kendra_index` resource referencing that key's ARN.
3. Grant the Kendra service role and any consuming applications the necessary `kms:Decrypt`/`kms:GenerateDataKey` permissions in the key policy.
4. Note: `server_side_encryption_configuration` for Kendra indexes is set at creation time — changing it on an existing index typically forces resource replacement (re-indexing required), so plan for a migration window.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/KendraIndexSSEUsesCMK.py
- AWS documentation: https://docs.aws.amazon.com/kendra/latest/dg/encryption-at-rest.html
