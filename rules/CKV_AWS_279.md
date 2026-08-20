# CKV_AWS_279: Ensure Neptune snapshot is securely encrypted
## Severity
**HIGH** (score: 7.5/10)

An unencrypted Neptune snapshot stores a full copy of graph database contents in plaintext, so anyone who can access or share the snapshot can read potentially sensitive data at rest.

## Summary
This check fails when an `aws_neptune_cluster_snapshot` resource does not set `storage_encrypted` to a truthy value, meaning the manual snapshot of a Neptune graph database cluster is not confirmed to be encrypted at rest.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource:** `aws_neptune_cluster_snapshot`

## Why it matters
Amazon Neptune cluster snapshots contain a full copy of the graph database's underlying storage — which can include highly sensitive relationship/graph data (e.g., fraud-detection graphs, identity/access graphs, social or knowledge graphs containing PII). Unlike the live cluster, a snapshot is a standalone artifact that can be shared, copied across accounts/regions, or restored independently — and its encryption status is fixed by the source cluster's `storage_encrypted` setting at the time it's created (Neptune cannot encrypt an existing unencrypted cluster's snapshot after the fact). If the source cluster is unencrypted, snapshot data at rest is unprotected against physical media compromise or misconfigured storage access, and restoring from that snapshot perpetuates the unencrypted state onto new clusters. It's a foundational encryption-at-rest control that also gates other capabilities like KMS-based access control (CKV_AWS_280) and cross-account snapshot sharing safety.

## How Checkov evaluates this
The check uses `BaseResourceValueCheck` and inspects the `storage_encrypted` attribute on `aws_neptune_cluster_snapshot`. It passes when the attribute is present and truthy; it fails when the attribute is missing/false — note that because Neptune snapshots inherit encryption from their source cluster, `storage_encrypted` here mirrors the source cluster's setting and cannot be changed independently on the snapshot resource.

## Non-compliant example
```hcl
resource "aws_neptune_cluster" "example" {
  cluster_identifier  = "example-cluster"
  engine              = "neptune"
  skip_final_snapshot = true
  # storage_encrypted not set -> defaults to false
}

resource "aws_neptune_cluster_snapshot" "example" {
  db_cluster_identifier          = aws_neptune_cluster.example.id
  db_cluster_snapshot_identifier = "example-snapshot"
  # storage_encrypted inherited as false from the unencrypted cluster
}
```

## Remediated example
```hcl
resource "aws_neptune_cluster" "example" {
  cluster_identifier  = "example-cluster"
  engine              = "neptune"
  skip_final_snapshot = true
  storage_encrypted   = true
}

resource "aws_neptune_cluster_snapshot" "example" {
  db_cluster_identifier          = aws_neptune_cluster.example.id
  db_cluster_snapshot_identifier = "example-snapshot"
  storage_encrypted               = true
}
```

## Remediation steps
1. Set `storage_encrypted = true` on the source `aws_neptune_cluster` — encryption cannot be added retroactively to an existing unencrypted cluster or its snapshots.
2. For an already-unencrypted cluster, the only path to encryption is: snapshot it, copy the snapshot with encryption enabled (specifying a KMS key), then restore a new cluster from the encrypted copy — this requires a maintenance window/cutover.
3. Combine with CKV_AWS_280 to also specify a customer-managed KMS key (`kms_key_id`) rather than relying on the AWS-managed default key.
4. Verify any snapshot-sharing (cross-account) configuration is only applied to encrypted snapshots, since unencrypted snapshots cannot be shared cross-account at all in some configurations and encrypted ones require explicit KMS key grants.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NeptuneClusterSnapshotEncrypted.py
- AWS docs: https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html
