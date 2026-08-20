# CKV_AWS_96: Ensure all data stored in Aurora is securely encrypted at rest

## Severity
**HIGH** (score: 7.5/10)

Unencrypted Aurora storage leaves data at rest exposed if underlying storage, snapshots, or backups are ever accessed outside normal access controls (e.g., via a misconfigured snapshot share).

## Summary
This check fails when an Amazon Aurora DB cluster does not have `StorageEncrypted`/`storage_encrypted` set to `true`, meaning the underlying cluster storage is not encrypted at rest.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_rds_cluster` resource — inspects `storage_encrypted` (with a special pass-through for `engine_mode = "serverless"`).
- **CloudFormation**: `AWS::RDS::DBCluster` resource — inspects `Properties.StorageEncrypted` (with special handling when `SnapshotIdentifier`/`SourceDBClusterIdentifier` is set).

## Why it matters
Aurora clusters commonly host an organization's primary relational data — customer records, financial transactions, application state — making them one of the highest-value targets for data exposure. Storage encryption (AES-256 via AWS KMS) protects the underlying EBS-backed storage, automated backups, snapshots, and read replicas from exposure if the physical storage layer, a snapshot, or a backup is ever accessed outside of normal application paths (e.g., an improperly shared snapshot, a decommissioned volume that isn't properly wiped, or unauthorized access at the storage/hypervisor layer). It's also frequently a hard compliance requirement (PCI-DSS, HIPAA, SOC 2) for at-rest protection of regulated data. Critically, `storage_encrypted` **cannot be changed on an existing, already-unencrypted cluster** — turning it on later requires creating a new encrypted cluster from a snapshot and cutting traffic over, so getting this right at creation time avoids a costly migration.

## How Checkov evaluates this
- **Terraform**: If `engine_mode == "serverless"`, the check auto-passes (Aurora Serverless is always encrypted per AWS documentation, snapshots included). Otherwise it inspects `storage_encrypted`, expecting `true` — anything else (absent, `false`) is FAILED.
- **CloudFormation**: If `SnapshotIdentifier` or `SourceDBClusterIdentifier` is present in `Properties`, the check returns `UNKNOWN` — because when restoring from a snapshot or creating a read replica of an existing cluster, the encryption state is *inherited* from the source and cannot be determined from the template alone (setting `StorageEncrypted` explicitly in that case is actually invalid per AWS documentation). Otherwise, it inspects `Properties.StorageEncrypted` and expects `true`.

## Non-compliant example
```hcl
resource "aws_rds_cluster" "app" {
  cluster_identifier      = "app-cluster"
  engine                    = "aurora-postgresql"
  master_username           = "admin"
  master_password           = var.db_password
  storage_encrypted         = false
}
```

## Remediated example
```hcl
resource "aws_kms_key" "aurora" {
  description = "KMS key for Aurora cluster encryption"
}

resource "aws_rds_cluster" "app" {
  cluster_identifier      = "app-cluster"
  engine                    = "aurora-postgresql"
  master_username           = "admin"
  master_password           = var.db_password
  storage_encrypted         = true
  kms_key_id                = aws_kms_key.aurora.arn
}
```

## Remediation steps
1. Set `storage_encrypted = true` (Terraform) or `StorageEncrypted: true` (CloudFormation), ideally with an explicit `kms_key_id`/`KmsKeyId` pointing to a customer-managed KMS key for auditability and key-rotation control.
2. **This attribute cannot be toggled on an existing unencrypted cluster.** To remediate a running unencrypted cluster: take a snapshot, copy the snapshot with encryption enabled (specifying a KMS key), restore a new cluster from the encrypted snapshot copy, then cut application traffic over and decommission the old cluster — this requires planning for a migration/cutover window.
3. If using Aurora Serverless (`engine_mode = "serverless"`), no explicit `storage_encrypted` setting is required — it's always encrypted.
4. When restoring from a snapshot or creating a cluster from `snapshot_identifier`, do not set `storage_encrypted` explicitly — the value is inherited from the source; instead confirm the *source* snapshot was encrypted.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AuroraEncryption.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/AuroraEncryption.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Overview.Encryption.html
