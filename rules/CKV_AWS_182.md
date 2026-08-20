# CKV_AWS_182: Ensure DocumentDB is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

DocumentDB commonly stores application/customer data, and while this check is limited to requiring a customer-managed (vs. AWS-managed) KMS key, losing customer control over key rotation and access revocation for a database is a meaningful, if not critical, risk.

## Summary
This check requires that an `aws_docdb_cluster` resource specify a customer-managed KMS key (`kms_key_id`) for storage encryption instead of the AWS-managed default key.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_docdb_cluster`
- **Check type:** resource (attribute-value check)

## Why it matters
Amazon DocumentDB clusters store MongoDB-compatible document data that frequently includes application state, user records, and other sensitive business data. While DocumentDB supports encryption at rest, if it's enabled without an explicit CMK it falls back to an AWS-owned/managed key that your team cannot govern. A customer-managed key lets you enforce least-privilege key policies (only specific IAM roles can decrypt), rotate the key on your own schedule, and — most importantly — instantly revoke database-wide decrypt access by disabling the key if a breach is suspected, which is impossible with the default key. Auditors reviewing database encryption controls (e.g. for PCI-DSS or HIPAA) typically require evidence of CMK usage with documented key policies and CloudTrail-based access review, not just "encryption enabled."

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `kms_key_id` attribute of `aws_docdb_cluster`. It expects `ANY_VALUE` — any non-empty value passes. Note this check only validates that a KMS key ID is present; it does not separately verify `storage_encrypted = true` (that is covered by a different Checkov rule), so a resource could still fail overall security if encryption itself is disabled — but for this specific rule, absence of `kms_key_id` is the failing condition.

## Non-compliant example
```hcl
resource "aws_docdb_cluster" "example" {
  cluster_identifier      = "app-docdb"
  engine                  = "docdb"
  master_username         = "admin"
  master_password         = var.docdb_password
  storage_encrypted       = true
  # kms_key_id not set -- uses AWS-owned default key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "docdb" {
  description             = "CMK for DocumentDB encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_docdb_cluster" "example" {
  cluster_identifier = "app-docdb"
  engine              = "docdb"
  master_username     = "admin"
  master_password     = var.docdb_password
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.docdb.arn  # customer managed key
}
```

## Remediation steps
1. Create or select a customer-managed KMS key with a key policy restricted to the DocumentDB service principal and the operational roles that need database access.
2. Set `storage_encrypted = true` and `kms_key_id` on the `aws_docdb_cluster` resource.
3. Enable automatic key rotation on the CMK.
4. Important caveat: encryption (and the KMS key used) can only be set at cluster creation time — you cannot change `kms_key_id` on an existing unencrypted or default-key-encrypted cluster in place. Migrating requires creating a new encrypted cluster and restoring/migrating data (e.g., via `mongodump`/`mongorestore` or a snapshot copy re-encrypted with the CMK), causing downtime.
5. Verify the DocumentDB service role and application IAM roles have `kms:Decrypt` and `kms:CreateGrant` on the CMK.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DocDBEncryptedWithCMK.py)
- [AWS DocumentDB encryption at rest documentation](https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html)
