# CKV_AWS_146: Ensure that RDS database cluster snapshot is encrypted
## Severity
**LOW** (score: 2.0/10)

An RDS cluster snapshot is a full point-in-time copy of a database's contents, and an unencrypted snapshot can be shared, copied, or restored outside the original security boundary, directly exposing sensitive data at rest.

## Summary
This check verifies that an `aws_db_cluster_snapshot` resource has `storage_encrypted` set to `true`, ensuring manual snapshots of an RDS/Aurora cluster are encrypted at rest.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to the `aws_db_cluster_snapshot` resource.

## Why it matters
A DB cluster snapshot is a full point-in-time copy of the database's storage, including all rows, indexes, and any sensitive data (PII, credentials, financial records) that live in the source database. Snapshots can be copied across accounts and regions, shared with other AWS accounts, and restored to a new cluster — making them a common exfiltration or lateral-movement vector if unencrypted. If storage_encrypted is false, the snapshot (and any cluster restored from it) stores data in plaintext on the underlying storage medium, meaning anyone who gains access to the snapshot artifact (e.g. through an over-permissive snapshot-sharing configuration or account compromise) can read the data directly without needing to obtain a KMS decrypt grant.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `storage_encrypted` attribute of `aws_db_cluster_snapshot`. It passes only when `storage_encrypted = true`; it fails when the attribute is `false` or omitted (Terraform/AWS defaults `storage_encrypted` to `false` if not specified).

## Non-compliant example
```hcl
resource "aws_db_cluster_snapshot" "manual" {
  db_cluster_identifier          = aws_rds_cluster.main.id
  db_cluster_snapshot_identifier = "manual-snapshot-2026-08"
}
```

## Remediated example
```hcl
resource "aws_db_cluster_snapshot" "manual" {
  db_cluster_identifier          = aws_rds_cluster.main.id
  db_cluster_snapshot_identifier = "manual-snapshot-2026-08"
  storage_encrypted              = true # <-- added
}
```

## Remediation steps
1. Ensure the *source* `aws_rds_cluster` itself is created with `storage_encrypted = true` — a snapshot of an unencrypted cluster cannot be encrypted after the fact by setting this attribute alone; the encryption state is inherited from the source cluster's storage.
2. If the source cluster is currently unencrypted, the standard remediation path is: create an encrypted copy via `aws_db_cluster_snapshot` copy with a KMS key, or restore-and-re-create the cluster from an encrypted snapshot — this requires a maintenance window and effectively means replacing the cluster.
3. Explicitly set `storage_encrypted = true` in Terraform so future plans don't drift back to the default.
4. Optionally specify `kms_key_id` if you need a customer-managed key rather than the AWS-managed `aws/rds` key.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSClusterSnapshotEncrypted.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Overview.Encryption.html
