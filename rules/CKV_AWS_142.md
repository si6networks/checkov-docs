# CKV_AWS_142: Ensure that Redshift cluster is encrypted by KMS

## Severity
**LOW** (score: 2.0/10)

An unencrypted Redshift cluster stores data warehouse contents — often sensitive analytical or business data — in plaintext at rest, exposing it if underlying storage, snapshots, or backups are accessed improperly.

## Summary
This check requires `aws_redshift_cluster` resources to set a `kms_key_id`, ensuring the cluster's at-rest encryption uses a customer-specified KMS key rather than being left unencrypted or using only default settings.

## Applicability
- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_redshift_cluster`

## Why it matters
Amazon Redshift clusters commonly hold aggregated analytical data drawn from many source systems — often including sensitive business data, customer PII, or financial records consolidated for reporting. If the cluster is unencrypted, that data (including automated snapshots) is stored in plaintext, so any exposure of underlying storage or snapshots (e.g., mistakenly shared snapshots, storage-layer access, or improper cross-account sharing) discloses the data directly. Requiring a KMS key also means encryption/decryption operations are governed by an explicit key policy, giving you control over exactly which IAM principals can decrypt the data and a durable CloudTrail record of key usage — critical for both breach containment (revoke key access) and after-the-fact forensic/audit trails.

## How Checkov evaluates this
The check (`RedshiftClusterKMSKey`, `BaseResourceValueCheck`) uses `ANY_VALUE` as the expected value:
- Inspects the `kms_key_id` attribute.
- **PASS** if `kms_key_id` is set to any non-empty value.
- **FAIL** if the attribute is absent or empty.

Note: the check only verifies that a KMS key ID is specified — it does not separately check the `encrypted` attribute, though in practice AWS requires `encrypted = true` for `kms_key_id` to take effect.

## Non-compliant example
```hcl
resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier = "app-warehouse"
  node_type           = "dc2.large"
  master_username     = "admin"
  master_password     = var.redshift_password
  # kms_key_id not set -> FAIL
}
```

## Remediated example
```hcl
resource "aws_kms_key" "redshift" {
  description         = "KMS key for Redshift cluster encryption"
  enable_key_rotation = true
}

resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier = "app-warehouse"
  node_type           = "dc2.large"
  master_username     = "admin"
  master_password     = var.redshift_password
  encrypted           = true
  kms_key_id          = aws_kms_key.redshift.arn   # added
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key dedicated to Redshift encryption, and enable automatic key rotation.
2. Set both `encrypted = true` and `kms_key_id = <key-arn>` on the `aws_redshift_cluster` resource.
3. **Important:** encryption settings (`encrypted`, `kms_key_id`) generally cannot be changed on a running, already-unencrypted cluster in place — enabling encryption on an existing unencrypted cluster requires creating a new encrypted cluster from a snapshot (AWS supports "modify to enable encryption" via a snapshot-restore workflow, which involves a resize/migration event and temporary downtime or a cutover window).
4. Grant the KMS key policy `kms:Decrypt`/`kms:CreateGrant` permissions to the Redshift service principal and any IAM roles that need to query the cluster.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshiftClusterKMSKey.py)
- [AWS: Amazon Redshift database encryption](https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html)
