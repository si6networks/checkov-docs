# CKV_AWS_280: Ensure Neptune snapshot is encrypted by KMS using a customer managed Key (CMK)
## Severity
**HIGH** (score: 7.5/10)

Like other CMK-vs-default-key checks, the underlying Neptune snapshot is already encrypted; using AWS-managed rather than a customer-managed key only weakens key governance and revocation control, not confidentiality of the data itself.

## Summary
This check fails when an `aws_neptune_cluster_snapshot` resource does not set a `kms_key_id`, meaning the snapshot's encryption key management is not confirmed to use a customer-managed key.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource:** `aws_neptune_cluster_snapshot`

## Why it matters
Neptune snapshot encryption is inherited from the source cluster; when it relies on the AWS-managed default KMS key rather than a customer-managed key (CMK), your organization loses the ability to independently control the key's rotation schedule, key policy (who may `Decrypt`/`Encrypt`/grant access), and CloudTrail-auditable key usage. A CMK is required to implement fine-grained separation of duties (e.g., DBAs can manage the cluster but not decrypt snapshots without a separate key-admin grant), to support cross-account snapshot sharing safely (AWS-managed keys cannot be shared cross-account), and to satisfy compliance frameworks that mandate customer control over encryption keys used for regulated data. Graph data in Neptune (identity graphs, fraud graphs, relationship data) is often sensitive enough to warrant this level of key custody control.

## How Checkov evaluates this
The check uses `BaseResourceValueCheck` with `get_expected_value` returning `ANY_VALUE`, inspecting the `kms_key_id` attribute on `aws_neptune_cluster_snapshot`. It passes if `kms_key_id` is set to any value, and fails if the attribute is absent.

## Non-compliant example
```hcl
resource "aws_neptune_cluster_snapshot" "example" {
  db_cluster_identifier          = aws_neptune_cluster.example.id
  db_cluster_snapshot_identifier = "example-snapshot"
  # no kms_key_id specified
}
```

## Remediated example
```hcl
resource "aws_kms_key" "neptune" {
  description         = "CMK for Neptune cluster and snapshots"
  enable_key_rotation = true
}

resource "aws_neptune_cluster" "example" {
  cluster_identifier  = "example-cluster"
  engine              = "neptune"
  storage_encrypted   = true
  kms_key_arn         = aws_kms_key.neptune.arn
  skip_final_snapshot = true
}

resource "aws_neptune_cluster_snapshot" "example" {
  db_cluster_identifier          = aws_neptune_cluster.example.id
  db_cluster_snapshot_identifier = "example-snapshot"
  kms_key_id                     = aws_kms_key.neptune.key_id
}
```

## Remediation steps
1. Provision a dedicated customer-managed KMS key for Neptune (with rotation enabled) rather than relying on the AWS-managed `aws/neptune` default key.
2. Set `kms_key_arn` on the source `aws_neptune_cluster` at creation time (this cannot be changed after the cluster is created without snapshot/restore).
3. Set `kms_key_id` explicitly on the `aws_neptune_cluster_snapshot` resource to match.
4. Ensure the key policy grants the Neptune service and any snapshot-consuming principals the required `kms:Decrypt` / `kms:CreateGrant` permissions.
5. If migrating an existing cluster that uses the default AWS-managed key, plan a snapshot-copy-and-restore migration since the KMS key cannot be swapped in place on a running cluster.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NeptuneClusterSnapshotEncryptedWithCMK.py
- AWS docs: https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html
