# CKV_AWS_281: Ensure RedShift snapshot copy is encrypted by KMS using a customer managed Key (CMK)
## Severity
**HIGH** (score: 7.5/10)

The Redshift snapshot copy grant already implies encryption; failing this check means the copy relies on a non-customer-managed key, reducing control over key rotation/access rather than leaving data unencrypted.

## Summary
This check fails when an `aws_redshift_snapshot_copy_grant` resource does not set `kms_key_id`, meaning cross-region Redshift snapshot copies are not confirmed to use a customer-managed KMS key.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource:** `aws_redshift_snapshot_copy_grant`

## Why it matters
`aws_redshift_snapshot_copy_grant` authorizes Redshift to re-encrypt snapshots when copying them to another AWS region (cross-region snapshot copy, typically used for disaster recovery). If no customer-managed key is specified for the grant, the copy either falls back to an AWS-managed key or the copy operation lacks the intended cryptographic isolation between regions/accounts. Redshift snapshots contain full copies of data warehouse contents — often the most sensitive aggregated business data in an organization (financial records, customer PII, analytics on regulated data). Using a CMK for the copy grant ensures the destination-region copy is encrypted under a key your organization controls, can rotate, and can revoke access to independently of the source region's key — critical for meeting data-residency and key-custody requirements when snapshots cross regional or account boundaries.

## How Checkov evaluates this
The check uses `BaseResourceValueCheck` with `get_expected_value` returning `ANY_VALUE`, inspecting the `kms_key_id` attribute on `aws_redshift_snapshot_copy_grant`. It passes if any value is set for `kms_key_id`, and fails if the attribute is omitted.

## Non-compliant example
```hcl
resource "aws_redshift_snapshot_copy_grant" "example" {
  snapshot_copy_grant_name = "my-snapshot-copy-grant"
  # kms_key_id not specified
}
```

## Remediated example
```hcl
resource "aws_kms_key" "redshift_copy" {
  description         = "CMK for Redshift cross-region snapshot copies"
  enable_key_rotation = true
}

resource "aws_redshift_snapshot_copy_grant" "example" {
  snapshot_copy_grant_name = "my-snapshot-copy-grant"
  kms_key_id               = aws_kms_key.redshift_copy.key_id
}
```

## Remediation steps
1. Create a customer-managed KMS key in the destination region for snapshot copies.
2. Set `kms_key_id` on the `aws_redshift_snapshot_copy_grant` resource to that key's ID or ARN.
3. Ensure the Redshift cluster's own `kms_key_id` (on `aws_redshift_cluster`) is also a CMK so source-side encryption is consistent, and that the source cluster has `encrypted = true`.
4. Grant the Redshift service principal the necessary key policy permissions in both source and destination regions.
5. Note that changing the copy grant's key may require deleting and recreating the grant; coordinate with any active cross-region replication schedule to avoid a gap in DR coverage during the change.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshiftClusterSnapshotCopyGrantEncryptedWithCMK.py
- AWS docs: https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html
