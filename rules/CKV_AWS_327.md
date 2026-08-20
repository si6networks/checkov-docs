# CKV_AWS_327: Ensure RDS Clusters are encrypted using KMS CMKs
## Severity
**LOW** (score: 2.0/10)

An RDS cluster without KMS customer-managed-key encryption leaves data at rest without organization-controlled cryptographic protection, exposing sensitive database contents to anyone who obtains storage-level or snapshot access.

## Summary
This check requires that `aws_rds_cluster` resources set `kms_key_id` to a customer-managed KMS key (CMK), rather than relying on the AWS-managed default RDS key (or leaving encryption unconfigured).

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_rds_cluster`

## Why it matters
RDS clusters can be encrypted at rest either with the AWS-managed `aws/rds` key or with a customer-managed KMS key. Using a CMK gives you control over the key policy (who can use/administer the key), the ability to enforce key rotation on your own schedule, the ability to fully revoke access by disabling or deleting the key, and CloudTrail visibility into every cryptographic operation performed against your specific key. With the AWS-managed key, none of that granular control or auditability is available — you cannot restrict which principals may use the key beyond default IAM permissions, and you cannot independently disable it to cut off access in an incident. For workloads subject to compliance regimes (PCI DSS, HIPAA, FedRAMP) or where you need cryptographic separation between environments/tenants, a CMK is typically mandatory.

## How Checkov evaluates this
The check (`RDSClusterEncryptedWithCMK.py`) is a straightforward value check:
- It inspects the `kms_key_id` attribute.
- If `kms_key_id` is present and set to **any** value (`ANY_VALUE`), the check **PASSES**.
- If `kms_key_id` is absent, the check **FAILS**.

Note: this check only verifies that a KMS key ID is specified — it does not itself confirm `storage_encrypted = true` (that is covered by a separate encryption-enabled check) or validate that the referenced key is actually customer-managed rather than an alias for the AWS-managed key.

## Non-compliant example
```hcl
resource "aws_rds_cluster" "bad_example" {
  cluster_identifier  = "app-cluster"
  engine              = "aurora-postgresql"
  master_username     = "admin"
  master_password     = var.db_password
  storage_encrypted   = true
  # kms_key_id not set -> falls back to AWS-managed key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "rds_cmk" {
  description         = "CMK for RDS cluster encryption"
  enable_key_rotation = true
}

resource "aws_rds_cluster" "good_example" {
  cluster_identifier  = "app-cluster"
  engine              = "aurora-postgresql"
  master_username     = "admin"
  master_password     = var.db_password
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.rds_cmk.arn
}
```

## Remediation steps
1. Create (or identify an existing) customer-managed KMS key dedicated to RDS encryption, with `enable_key_rotation = true` and a key policy scoped to the principals/roles that legitimately need access.
2. Set `kms_key_id` on the `aws_rds_cluster` resource to that key's ARN or ID, and ensure `storage_encrypted = true` is also set.
3. **Caution:** `kms_key_id` cannot be changed on an existing encrypted cluster — encryption key selection is immutable after creation. Migrating an existing cluster to a CMK requires creating a new encrypted snapshot/cluster (via snapshot copy with the new KMS key) and cutting over, which involves downtime or a blue/green migration strategy.
4. Grant the RDS service and any cross-account principals (e.g., for snapshot sharing) the necessary `kms:Decrypt`/`kms:CreateGrant` permissions in the CMK's key policy.
5. Apply the same treatment to any read replicas and automated snapshots that need to remain encrypted with the same or a replica-region CMK.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSClusterEncryptedWithCMK.py)
- [AWS: Encrypting Amazon RDS resources](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html)
