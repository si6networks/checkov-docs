# CKV_AWS_201: Ensure MemoryDB is encrypted at rest using KMS CMKs
## Severity
**LOW** (score: 2.0/10)

MemoryDB clusters without KMS CMK encryption at rest leave cached application and session data unprotected against exposure via storage-level access, snapshots, or backups.

## Summary
Ensures that an Amazon MemoryDB for Redis cluster specifies a customer-managed KMS key (CMK) for at-rest encryption, rather than relying on the AWS-managed default key or leaving encryption unspecified.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_memorydb_cluster` — inspects the `kms_key_arn` attribute.

## Why it matters
MemoryDB clusters commonly hold session state, caching data, rate-limiting counters, or other in-memory application data that can include sensitive tokens or user identifiers persisted via MemoryDB's durable multi-AZ transaction log. Without a customer-managed key for at-rest encryption:
- You cannot independently control or revoke access to the encryption key via a dedicated KMS key policy — you're limited to whatever access the AWS-managed key allows, which cannot be scoped per-workload.
- You lose auditability: CMK usage generates `kms:Decrypt`/`kms:GenerateDataKey` CloudTrail events tied to a specific customer key, letting you monitor exactly when the cluster's data is being decrypted; the default key gives far less granular visibility.
- You cannot enforce separation of duties (e.g., different teams/accounts owning the key vs. the cluster) or meet compliance mandates that specifically require customer-controlled encryption keys (many regulated industries require CMK, not just "encryption enabled").

## How Checkov evaluates this
`MemoryDBEncryptionWithCMK` is a `BaseResourceValueCheck` expecting `ANY_VALUE` on the `kms_key_arn` attribute:
- If `kms_key_arn` is set to any value → PASS.
- If `kms_key_arn` is absent/empty → FAIL.

Note: MemoryDB encrypts data at rest by default even without a specified key (using an AWS-managed key), but this check specifically requires an explicit CMK reference — it does not just check that "some" encryption is enabled.

## Non-compliant example
```hcl
resource "aws_memorydb_cluster" "sessions" {
  name                 = "session-cache"
  node_type            = "db.r6g.large"
  num_shards           = 2
  acl_name             = "open-access"
  subnet_group_name    = aws_memorydb_subnet_group.main.name
  # No kms_key_arn set -> FAILS CKV_AWS_201 (uses AWS-managed key by default)
}
```

## Remediated example
```hcl
resource "aws_kms_key" "memorydb_cmk" {
  description         = "CMK for MemoryDB at-rest encryption"
  enable_key_rotation = true
}

resource "aws_memorydb_cluster" "sessions" {
  name                 = "session-cache"
  node_type            = "db.r6g.large"
  num_shards           = 2
  acl_name             = "open-access"
  subnet_group_name    = aws_memorydb_subnet_group.main.name
  kms_key_arn          = aws_kms_key.memorydb_cmk.arn   # fix
}
```

## Remediation steps
1. Create a dedicated customer-managed KMS key (with rotation enabled) for MemoryDB encryption.
2. Set `kms_key_arn` on the `aws_memorydb_cluster` resource to that key's ARN.
3. Grant the MemoryDB service and any consuming application roles the necessary `kms:Decrypt`/`kms:GenerateDataKey`/`kms:DescribeKey` permissions in the CMK's key policy.
4. Changing the KMS key on an existing cluster requires replacement (Terraform will show this as a forced new resource) — plan for a maintenance window, snapshot/restore, or blue-green cluster cutover rather than an in-place update.
5. Confirm the CMK exists in the same region as the MemoryDB cluster, since KMS keys (other than multi-region keys) are region-scoped.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MemoryDBEncryptionWithCMK.py
- AWS docs: https://docs.aws.amazon.com/memorydb/latest/devguide/at-rest-encryption.html
