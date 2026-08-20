# CKV_AWS_64: Ensure all data stored in the Redshift cluster is securely encrypted at rest
## Severity
**LOW** (score: 2.0/10)

An unencrypted Redshift cluster stores data warehouse contents (often sensitive analytical/business data) in plaintext, exposing it to anyone with access to the underlying storage, snapshots, or backups.

## Summary
This check verifies that an Amazon Redshift cluster has encryption at rest enabled (`Encrypted`/`encrypted` = `true`), so that data stored on the cluster's disks is encrypted rather than stored in plaintext.

## Applicability
- **CloudFormation**: `AWS::Redshift::Cluster`, property `Properties/Encrypted`.
- **Terraform**: `aws_redshift_cluster` resource, attribute `encrypted`.

## Why it matters
Redshift clusters commonly hold an organization's most sensitive and highest-volume analytical data — aggregated customer records, financial data, PII, or data warehoused from multiple upstream systems. Without at-rest encryption, the underlying EBS volumes, snapshots, and backups storing this data are unencrypted; if underlying storage media is improperly decommissioned, if a snapshot is inadvertently shared or made public, or if an attacker gains access to the underlying storage layer through an AWS-level vulnerability or misconfigured snapshot sharing, the data is directly readable. Because Redshift is typically a data-consolidation point (a "single pane of glass" over many sources), a Redshift breach can expose far more data than a breach of any single upstream source, making at-rest encryption a baseline compliance requirement (PCI-DSS, HIPAA, SOC 2) for virtually any production deployment.

## How Checkov evaluates this
Both are `BaseResourceValueCheck` implementations (no custom logic beyond the base attribute-value comparison):
- **CloudFormation**: inspects `Properties/Encrypted`.
- **Terraform**: inspects `encrypted`.
- PASS: value is `true`.
- FAIL: value is `false`, or the attribute is not set at all (Redshift's default for `encrypted` is `false` if omitted).

## Non-compliant example
```hcl
resource "aws_redshift_cluster" "analytics" {
  cluster_identifier = "analytics-cluster"
  database_name      = "analytics"
  master_username    = "admin"
  master_password    = var.redshift_password
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  # encrypted not set -> defaults to false, non-compliant
}
```

## Remediated example
```hcl
resource "aws_kms_key" "redshift" {
  description         = "Redshift cluster encryption key"
  enable_key_rotation = true
}

resource "aws_redshift_cluster" "analytics" {
  cluster_identifier = "analytics-cluster"
  database_name      = "analytics"
  master_username    = "admin"
  master_password    = var.redshift_password
  node_type          = "dc2.large"
  cluster_type       = "single-node"

  encrypted  = true                    # fixed
  kms_key_id = aws_kms_key.redshift.arn
}
```

## Remediation steps
1. Set `encrypted = true` (Terraform) or `Encrypted: true` (CloudFormation) on the cluster resource.
2. Optionally specify `kms_key_id` to use a customer-managed KMS key instead of the AWS-managed default Redshift key, for control over key policy and rotation.
3. **Important caveat**: enabling encryption on an existing, unencrypted Redshift cluster is not an in-place update — AWS performs this by creating a new encrypted cluster from a snapshot of the old one and swapping the endpoint, which involves downtime and, in Terraform, will force a resource replacement (destroy/recreate) since `encrypted` is not modifiable in place. Plan a maintenance window and verify application reconnect logic.
4. Ensure backups/snapshots inherit encryption — once the source cluster is encrypted, its automated snapshots and manual snapshots are also encrypted.
5. Restrict `kms:Decrypt` on the encryption key to only the principals/services that need it.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/RedshiftClusterEncryption.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshiftClusterEncryption.py)
- [AWS: Amazon Redshift database encryption](https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html)
