# CKV_AWS_292: Ensure DocumentDB Global Cluster is encrypted at rest (default is unencrypted)
## Severity
**HIGH** (score: 7.5/10)

This check verifies DocumentDB Global Cluster storage encryption is enabled; missing encryption at rest exposes data if underlying storage or snapshots are compromised, but exploitation requires separate access to the storage layer.

## Summary
This check ensures that an `aws_docdb_global_cluster` resource has `storage_encrypted` explicitly set to `true`, since Amazon DocumentDB global clusters are unencrypted by default.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_docdb_global_cluster`

## Why it matters
DocumentDB Global Clusters replicate data across AWS regions to support disaster recovery and low-latency global reads. If storage encryption is not enabled, all data at rest in the cluster's underlying storage volumes — including primary and secondary region replicas, automated backups, and snapshots — is stored unencrypted. This exposes sensitive data (documents, credentials embedded in application data, PII) to anyone with access to the underlying storage medium, violates common compliance frameworks (PCI DSS, HIPAA, SOC 2) that mandate encryption at rest for regulated data, and removes a defense-in-depth layer that would otherwise limit the blast radius of a storage-level compromise or misconfigured snapshot share. Because DocumentDB storage encryption can only be enabled at cluster creation time (it cannot be turned on for an existing unencrypted cluster), a global cluster deployed without it requires a full rebuild and data migration to remediate later — making it critical to catch at the IaC review stage.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (Python check). It inspects the `storage_encrypted` attribute of the `aws_docdb_global_cluster` resource block:
- **PASS** if `storage_encrypted = true` is set.
- **FAIL** if the attribute is absent (the AWS default is unencrypted) or explicitly set to `false`.

## Non-compliant example
```hcl
resource "aws_docdb_global_cluster" "example" {
  global_cluster_identifier = "global-docdb-cluster"
  engine                    = "docdb"
  engine_version            = "5.0.0"
  # storage_encrypted not set -> defaults to unencrypted, check FAILS
}
```

## Remediated example
```hcl
resource "aws_docdb_global_cluster" "example" {
  global_cluster_identifier = "global-docdb-cluster"
  engine                    = "docdb"
  engine_version            = "5.0.0"
  storage_encrypted         = true   # explicitly enable encryption at rest
}
```

## Remediation steps
1. Add `storage_encrypted = true` to every `aws_docdb_global_cluster` resource block.
2. Storage encryption is immutable after cluster creation — this setting **cannot** be applied to an already-provisioned global cluster via `terraform apply` alone; it requires creating a new encrypted cluster and migrating data (expect downtime or a cutover window).
3. If you need a specific key rather than the AWS-managed default, also configure `kms_key_id` on the primary cluster (the global cluster inherits encryption settings from its primary member cluster in most configurations) — verify against the current AWS provider documentation for how `storage_encrypted`/`kms_key_id` interact between `aws_docdb_global_cluster` and `aws_docdb_cluster`.
4. Add an org-wide Sentinel/OPA or Checkov CI gate so future global clusters cannot be merged without this attribute set.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DocDBGlobalClusterEncryption.py)
