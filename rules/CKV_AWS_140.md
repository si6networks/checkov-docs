# CKV_AWS_140: Ensure that RDS global clusters are encrypted

## Severity
**LOW** (score: 2.0/10)

Unencrypted RDS global clusters store potentially sensitive relational data across regions without protection at rest, exposing it to anyone who gains access to the underlying storage or snapshots.

## Summary
This check requires `aws_rds_global_cluster` resources to set `storage_encrypted = true`, ensuring data across all regional clusters in the Aurora Global Database is encrypted at rest.

## Applicability
- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_rds_global_cluster`

## Why it matters
An unencrypted RDS/Aurora global cluster stores database files, automated backups, snapshots, and replica data in plaintext at the storage layer. If underlying storage media, snapshots, or backups are ever exposed — through misconfigured snapshot sharing, an insider with storage-level access, or a cloud provider-side failure — the data is directly readable with no additional barrier. This is especially significant for a *global* cluster, since it can span multiple AWS regions and thus multiplies the number of storage locations, backup copies, and jurisdictions where unencrypted data at rest would exist. Many compliance regimes (PCI-DSS, HIPAA, GDPR-adjacent data residency/protection expectations) require encryption at rest for regulated data, and this becomes harder to demonstrate across a multi-region topology without encryption enabled uniformly from the start.

## How Checkov evaluates this
The check (`RDSClusterEncrypted`, `BaseResourceCheck`):
- If `source_db_cluster_identifier` is set (the global cluster is being created from an existing source cluster/snapshot), the result is **UNKNOWN** — encryption in that case is inherited from the source and can't be determined from this resource's config alone.
- Otherwise, it inspects `storage_encrypted`: **PASS** if `true`; **FAIL** if `false`.
- If `storage_encrypted` is **absent entirely**, the check also **FAILS** (no benefit-of-the-doubt default).

## Non-compliant example
```hcl
resource "aws_rds_global_cluster" "global" {
  global_cluster_identifier = "app-global"
  engine                    = "aurora-postgresql"
  engine_version            = "13.4"
  # storage_encrypted not set -> FAIL
}
```

## Remediated example
```hcl
resource "aws_rds_global_cluster" "global" {
  global_cluster_identifier = "app-global"
  engine                    = "aurora-postgresql"
  engine_version            = "13.4"
  storage_encrypted         = true   # added
}
```

## Remediation steps
1. Add `storage_encrypted = true` to the `aws_rds_global_cluster` resource.
2. **Important:** `storage_encrypted` can only be set at cluster creation time; changing it on an existing unencrypted global cluster requires recreating the cluster (and its member clusters), typically via snapshot-and-restore into a new encrypted global cluster — plan for a migration window.
3. If the global cluster is created from an existing source database (`source_db_cluster_identifier`), ensure that source cluster is itself encrypted, since encryption is inherited and this Checkov check cannot verify it directly in that scenario (it returns UNKNOWN).
4. Decide whether to use the AWS-managed default KMS key or a customer-managed KMS key (`kms_key_id` on the underlying regional `aws_rds_cluster` resources) for more granular key-policy control.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSClusterEncrypted.py)
- [AWS: Encrypting Amazon Aurora resources](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Overview.Encryption.html)
