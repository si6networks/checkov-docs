# CKV_AWS_74: Ensure DocumentDB is encrypted at rest (default is unencrypted)
## Severity
**MEDIUM** (score: 5.0/10)

An unencrypted DocumentDB cluster leaves data at rest (potentially including sensitive application data) exposed to disclosure if underlying storage, snapshots, or backups are ever compromised.

## Summary
This check fails when an Amazon DocumentDB cluster does not have storage encryption enabled, which is important because DocumentDB clusters are **unencrypted by default**.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::DocDB::DBCluster` (CloudFormation), `aws_docdb_cluster` (Terraform)
- **Check type:** resource

## Why it matters
DocumentDB (MongoDB-compatible) clusters commonly store application-level document data, which can include PII, credentials, session tokens, or other sensitive business data. Without storage encryption, the underlying EBS-backed storage volumes, automated backups, snapshots, and read replicas are all held in plaintext at rest. If underlying storage media, a snapshot, or a backup is ever exposed (e.g., through a misconfigured snapshot-sharing permission, an insider with storage-layer access, or a cloud provider-level incident), the data is trivially readable. Because AWS does not enable this by default, teams frequently miss it during cluster creation, and — critically — **enabling encryption after cluster creation is not a simple flag flip: it requires creating a new encrypted cluster and migrating data**, making this a check best caught before deployment rather than remediated after the fact.

## How Checkov evaluates this
Both implementations extend `BaseResourceValueCheck` with a default expected value of `True`:
- **CloudFormation:** inspects `Properties/StorageEncrypted` on `AWS::DocDB::DBCluster`; passes only if explicitly `true`.
- **Terraform:** inspects the `storage_encrypted` attribute on `aws_docdb_cluster`; passes only if explicitly `true`. If absent, Terraform/AWS defaults to unencrypted, so the check fails.

## Non-compliant example
```hcl
resource "aws_docdb_cluster" "app_docs" {
  cluster_identifier      = "app-documents-cluster"
  engine                  = "docdb"
  master_username         = "dbadmin"
  master_password         = "ChangeMe123!"
  skip_final_snapshot     = true
}
```

```yaml
Resources:
  AppDocsCluster:
    Type: AWS::DocDB::DBCluster
    Properties:
      DBClusterIdentifier: app-documents-cluster
      MasterUsername: dbadmin
      MasterUserPassword: ChangeMe123!
```

## Remediated example
```hcl
resource "aws_docdb_cluster" "app_docs" {
  cluster_identifier      = "app-documents-cluster"
  engine                  = "docdb"
  master_username         = "dbadmin"
  master_password         = "ChangeMe123!"
  skip_final_snapshot     = true
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.docdb.arn
}
```

```yaml
Resources:
  AppDocsCluster:
    Type: AWS::DocDB::DBCluster
    Properties:
      DBClusterIdentifier: app-documents-cluster
      MasterUsername: dbadmin
      MasterUserPassword: ChangeMe123!
      StorageEncrypted: true
      KmsKeyId: !Ref DocDbKmsKey
```

## Remediation steps
1. Set `storage_encrypted = true` (Terraform) / `StorageEncrypted: true` (CloudFormation) on the cluster resource.
2. Optionally supply `kms_key_id` / `KmsKeyId` to use a customer-managed KMS key instead of the AWS-managed default key, for tighter key-policy and rotation control.
3. **This attribute cannot be changed on an existing cluster.** If you have an unencrypted cluster already running in production, you must: take a final snapshot, copy the snapshot with encryption enabled (`aws docdb copy-db-cluster-snapshot --target-db-cluster-snapshot-identifier ... --kms-key-id ...`), restore a new encrypted cluster from that snapshot, cut over application connections, then decommission the old cluster — plan for a maintenance window.
4. Update any Terraform state/import workflows accordingly since this change effectively requires a `terraform apply` that replaces the resource if changed post-creation (Terraform will error/require replacement).

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DocDBEncryption.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/DocDBEncryption.py)
- [Amazon DocumentDB encryption at rest](https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html)
