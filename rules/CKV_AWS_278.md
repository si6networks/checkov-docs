# CKV_AWS_278: Ensure MemoryDB snapshot is encrypted by KMS using a customer managed Key (CMK)
## Severity
**HIGH** (score: 7.5/10)

MemoryDB snapshots not using a customer-managed KMS key still get default encryption at rest, so the gap is reduced key-management control (rotation, revocation) rather than unencrypted, exposed data.

## Summary
This check fails when an `aws_memorydb_snapshot` resource does not specify a KMS `kms_key_arn`, meaning the snapshot is not confirmed to be encrypted with a customer-managed key.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource:** `aws_memorydb_snapshot`

## Why it matters
MemoryDB snapshots contain a point-in-time copy of everything held in the in-memory data store — which for Redis-compatible caches frequently includes session tokens, cached API responses, rate-limit counters, or even application-level secrets cached for performance. Snapshots persist this data to durable storage (S3-backed under the hood) outside the encrypted-in-memory boundary of the running cluster. Without a customer-managed KMS key, encryption of the snapshot (if any) is controlled entirely by AWS-managed keys, meaning your organization cannot independently rotate, restrict, audit key usage via CloudTrail, or revoke access to the encryption key without going through AWS default policies. A CMK gives you granular IAM/key-policy control over who can decrypt the snapshot and lets you meet compliance regimes that require customer control of encryption keys (e.g., certain data-residency or key-custody requirements).

## How Checkov evaluates this
The check uses `BaseResourceValueCheck` and inspects the `kms_key_arn` attribute on `aws_memorydb_snapshot`. The expected value is `ANY_VALUE`, meaning the check passes as long as `kms_key_arn` is set to *any* non-empty value (it does not validate that the key is actually customer-managed vs. AWS-managed beyond the attribute being present) — and fails if the attribute is omitted entirely.

## Non-compliant example
```hcl
resource "aws_memorydb_snapshot" "example" {
  cluster_name = aws_memorydb_cluster.example.name
  name         = "my-snapshot"
  # no kms_key_arn set
}
```

## Remediated example
```hcl
resource "aws_kms_key" "memorydb" {
  description             = "CMK for MemoryDB snapshots"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_memorydb_snapshot" "example" {
  cluster_name = aws_memorydb_cluster.example.name
  name         = "my-snapshot"
  kms_key_arn  = aws_kms_key.memorydb.arn
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key dedicated to MemoryDB data, with key rotation enabled.
2. Set `kms_key_arn` on the `aws_memorydb_snapshot` resource to that key's ARN.
3. Also set `kms_key_arn` on the parent `aws_memorydb_cluster` so live cluster data and its snapshots share consistent key management.
4. Grant the MemoryDB service principal (`memorydb.amazonaws.com`) the necessary `kms:Decrypt`/`kms:GenerateDataKey` permissions in the key policy.
5. Note: changing `kms_key_arn` on an existing resource may force replacement — check the Terraform plan carefully before applying to production snapshots, and take a manual backup snapshot first if needed.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MemoryDBSnapshotEncryptionWithCMK.py
- AWS docs: https://docs.aws.amazon.com/memorydb/latest/devguide/data-security.html
