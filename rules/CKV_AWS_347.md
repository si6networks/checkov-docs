# CKV_AWS_347: Ensure Neptune is encrypted by KMS using a customer managed Key (CMK)
## Severity
**HIGH** (score: 7.5/10)

Neptune clusters are encrypted at rest regardless, so missing a customer-managed KMS key reduces the operator's ability to independently rotate, audit, and revoke access to the encryption key for what can be sensitive graph-relationship data, rather than leaving the database unencrypted.

## Summary
Requires Amazon Neptune clusters to be encrypted using a customer-managed KMS key (via `kms_key_arn`) rather than the AWS-owned default key.

## Applicability
- **Framework**: Terraform
- **Resource type**: `aws_neptune_cluster`

## Why it matters
Amazon Neptune is a managed graph database often used to store highly relational, sensitive data (identity/access graphs, fraud-detection networks, knowledge graphs, social graphs) where the relationships themselves can be as sensitive as the underlying records. Encrypting the cluster's storage with an AWS-owned key means you have no visibility into who/what used the key to decrypt data, no ability to set a restrictive key policy limiting decrypt access to specific IAM principals, no independent rotation schedule, and no way to cryptographically revoke access to the data by disabling the key in an incident. Using a customer-managed key closes this gap: CloudTrail records every `kms:Decrypt`/`GenerateDataKey` call tied to the cluster, you control exactly which principals/roles can use the key, and you can immediately cut off all access to the encrypted data by disabling or scheduling deletion of the CMK — a critical incident-response capability and a common compliance requirement (HIPAA, PCI-DSS, FedRAMP) for data classified as sensitive.

## How Checkov evaluates this
This is a Terraform resource value check using the `ANY_VALUE` sentinel on the `kms_key_arn` attribute:
- **PASS**: `kms_key_arn` is set to any non-empty value (a CMK ARN).
- **FAIL**: `kms_key_arn` is absent or empty. Note: this check only verifies a CMK ARN is *specified* — it does not separately verify `storage_encrypted = true`; if you have a CMK but never enable storage encryption, that combination should be caught by companion Neptune encryption checks (e.g. CKV_AWS_44).

## Non-compliant example
```hcl
resource "aws_neptune_cluster" "graph" {
  cluster_identifier  = "graph-db"
  engine              = "neptune"
  storage_encrypted   = true
  # kms_key_arn omitted -> falls back to AWS-owned default key
  skip_final_snapshot = true
}
```

## Remediated example
```hcl
resource "aws_kms_key" "neptune" {
  description             = "CMK for Neptune cluster encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_neptune_cluster" "graph" {
  cluster_identifier  = "graph-db"
  engine              = "neptune"
  storage_encrypted   = true
  kms_key_arn         = aws_kms_key.neptune.arn   # customer-managed key
  skip_final_snapshot = true
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key with a key policy scoped to the roles/services that legitimately need to access the Neptune cluster's data.
2. Set `kms_key_arn` on the `aws_neptune_cluster` resource to that CMK's ARN, and ensure `storage_encrypted = true`.
3. **Important**: encryption settings (including the KMS key) can only be set at cluster creation time in Neptune — changing `kms_key_arn` on an existing unencrypted or differently-encrypted cluster requires creating a new encrypted cluster from a snapshot and migrating, not an in-place update. Plan for a maintenance window.
4. Enable automatic key rotation (`enable_key_rotation = true`) on the CMK.
5. Update IAM policies/roles that interact with Neptune to include the necessary `kms:Decrypt` grants for the new key.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NeptuneClusterEncryptedWithCMK.py
- AWS docs: https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html
