# CKV_AWS_266: Ensure DB Snapshot copy uses CMK

## Severity
**LOW** (score: 2.0/10)

RDS snapshot copies are full database dumps and a high-value target, but this check only governs which KMS key protects the copy, not whether encryption exists at all, so the gap is inconsistent/uncontrolled key governance across DR and cross-region copies.

## Summary
This check ensures that an `aws_db_snapshot_copy` (RDS DB snapshot copy) resource specifies a customer-managed KMS key ID for encrypting the copied snapshot.

## Applicability
- **Terraform**: resource `aws_db_snapshot_copy`

## Why it matters
RDS snapshots are full point-in-time copies of a database, including all stored data — often the single richest concentration of sensitive data in an AWS account. Copying a snapshot (frequently done to move it to another region, account, or for long-term archival/DR) is a moment where encryption configuration is easy to overlook, since the copy operation can silently inherit weaker defaults or use an AWS-owned key rather than an intentionally chosen CMK. If a copied snapshot ends up with a different (or no meaningful customer-managed) key than the source, an organization can lose consistent key-based access control across its DR/backup copies — meaning someone who shouldn't have decrypt access to the original could still access the copy if its key policy is more permissive, or an audit of "who can read our data" becomes fragmented across multiple keys.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` on the `kms_key_id` attribute:
- **PASS**: `kms_key_id` set to any non-empty value.
- **FAIL**: `kms_key_id` missing or empty.

## Non-compliant example
```hcl
resource "aws_db_snapshot_copy" "dr_copy" {
  source_db_snapshot_identifier = aws_db_snapshot.prod.db_snapshot_identifier
  target_db_snapshot_identifier = "prod-dr-copy"
  # no kms_key_id specified
}
```

## Remediated example
```hcl
resource "aws_db_snapshot_copy" "dr_copy" {
  source_db_snapshot_identifier = aws_db_snapshot.prod.db_snapshot_identifier
  target_db_snapshot_identifier = "prod-dr-copy"
  kms_key_id                    = aws_kms_key.rds_dr.arn
}
```

## Remediation steps
1. Identify (or create) the customer-managed KMS key intended for the destination account/region of the snapshot copy.
2. Set `kms_key_id` on the `aws_db_snapshot_copy` resource to that key's ARN.
3. If copying cross-region or cross-account, remember RDS snapshot copies cannot reuse a key from a different region — you must specify a key that exists in the destination region, and if cross-account, grant the destination account's principals decrypt permissions via the key policy.
4. If the source snapshot was already encrypted with a different key, note that RDS re-encrypts the copy with the key you specify here — verify this is the intended key rather than assuming inheritance.
5. This is generally not an in-place update; `aws_db_snapshot_copy` is typically a one-time/create-only resource, so correct the configuration before the next copy run rather than expecting a `terraform apply` to modify an existing snapshot's encryption.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DBSnapshotCopyUsesCMK.py
- AWS documentation: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CopySnapshot.html
