# CKV_AWS_44: Ensure Neptune storage is securely encrypted
## Severity
**MEDIUM** (score: 5.0/10)

Neptune graph database clusters typically hold relationship/identity data central to an application, and storing that data unencrypted at rest is a meaningful confidentiality exposure if storage-level access is compromised.

## Summary
This check ensures Amazon Neptune database clusters have storage encryption enabled at rest.

## Applicability
- **Frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::Neptune::DBCluster` (CloudFormation), `aws_neptune_cluster` (Terraform)

## Why it matters
Neptune is a managed graph database frequently used for storing relationship-rich, often sensitive data (identity/fraud graphs, knowledge graphs, social graphs, recommendation data). Without storage encryption, the underlying EBS-backed storage volumes, automated backups, snapshots, and read replicas are all stored in plaintext. Any exposure of the underlying storage — through an improperly shared snapshot, a decommissioned/repurposed disk, or a misconfigured backup export — would directly expose data. Storage encryption in Neptune is enforced at cluster-creation time and propagates to snapshots and replicas automatically, making it a low-friction, high-value control that is often required for compliance (HIPAA, PCI-DSS) when the graph contains regulated data.

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck`:
- **CloudFormation:** inspects `Properties/StorageEncrypted` on `AWS::Neptune::DBCluster` — **PASS** if `true`, **FAIL** if `false` or absent.
- **Terraform:** inspects the `storage_encrypted` argument on `aws_neptune_cluster` — **PASS** if `true`, **FAIL** if `false` or absent (Neptune clusters default to unencrypted storage).

## Non-compliant example
```hcl
resource "aws_neptune_cluster" "example" {
  cluster_identifier = "example-graph-db"
  engine             = "neptune"
  # storage_encrypted not set -> defaults to false
  skip_final_snapshot = true
}
```

## Remediated example
```hcl
resource "aws_neptune_cluster" "example" {
  cluster_identifier  = "example-graph-db"
  engine              = "neptune"
  storage_encrypted   = true
  kms_key_arn         = aws_kms_key.neptune.arn  # optional customer-managed key
  skip_final_snapshot = true
}
```

## Remediation steps
1. Set `storage_encrypted = true` on the `aws_neptune_cluster` resource (or `Properties/StorageEncrypted: true` in CloudFormation).
2. Optionally set `kms_key_arn` to use a customer-managed KMS key for tighter key-policy control; otherwise Neptune uses the default AWS-managed key.
3. **Important:** storage encryption cannot be enabled on an existing unencrypted Neptune cluster — you must create a new encrypted cluster (e.g., from an encrypted snapshot copy of the existing cluster) and cut applications over, since this requires resource replacement.
4. Plan for a maintenance window to perform the snapshot-copy-and-restore migration, and validate application connectivity against the new cluster endpoint before decommissioning the old one.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NeptuneClusterStorageEncrypted.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/NeptuneClusterStorageEncrypted.py)
- [AWS Neptune encryption at rest documentation](https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html)
