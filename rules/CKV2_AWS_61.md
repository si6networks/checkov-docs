# CKV2_AWS_61: Ensure that an S3 bucket has a lifecycle configuration

## Severity
**MEDIUM** (score: 5.0/10)

Missing S3 lifecycle rules mainly affects storage cost and data retention hygiene (e.g., stale objects/old versions lingering), an availability/governance concern rather than a direct exposure or access-control weakness.

## Summary
This check requires every `aws_s3_bucket` to have lifecycle rules defined — either via a connected `aws_s3_bucket_lifecycle_configuration` resource, or (for older provider syntax) an inline `lifecycle_rule` block — so that old/noncurrent object versions and stale data are automatically transitioned or expired rather than accumulating indefinitely.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_s3_bucket` (must be connected to `aws_s3_bucket_lifecycle_configuration`, OR have an inline `lifecycle_rule` attribute)

## Why it matters
Buckets without a lifecycle policy accumulate objects, noncurrent versions (when versioning is on), and incomplete multipart uploads without bound. Beyond runaway storage cost, this has real security and compliance implications: data retention requirements (GDPR, HIPAA, internal data-minimization policy) are frequently violated when stale data — including old backups, logs, or previous versions of sensitive files — is never purged, expanding the pool of data available to an attacker who compromises the bucket and increasing exposure in the event of a breach. Lifecycle rules also support security hygiene indirectly by expiring old access logs and temporary data, and by cleaning up abandoned multipart uploads that can otherwise silently consume storage and billing.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy) with an `or` of two paths:
1. **Connection path:** the resource is `aws_s3_bucket` and it has a graph **connection** to an `aws_s3_bucket_lifecycle_configuration` resource (referencing it via `bucket`).
2. **Inline path:** the `aws_s3_bucket` resource itself has a `lifecycle_rule` attribute present (the older, deprecated inline syntax).

If neither condition holds — no connected lifecycle configuration resource and no inline `lifecycle_rule` block — the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "audit_logs" {
  bucket = "acme-audit-logs"
}
# No lifecycle_rule block and no aws_s3_bucket_lifecycle_configuration -> FAILS
```

## Remediated example
```hcl
resource "aws_s3_bucket" "audit_logs" {
  bucket = "acme-audit-logs"
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
```

## Remediation steps
1. Add an `aws_s3_bucket_lifecycle_configuration` resource referencing the bucket (the modern, decoupled resource in AWS provider v4+), rather than the deprecated inline `lifecycle_rule` on `aws_s3_bucket`.
2. Define at least one `rule` block with `status = "Enabled"` and an appropriate action: `expiration`, `transition` (e.g., to `STANDARD_IA` or `GLACIER`), or `noncurrent_version_expiration` if versioning is enabled.
3. Always add `abort_incomplete_multipart_upload` to avoid silent storage cost/leakage from abandoned uploads.
4. Align retention days with your actual compliance/data-retention requirements — don't default to an arbitrary short window for data subject to legal hold or audit requirements.
5. If migrating from inline `lifecycle_rule` to the separate resource, plan carefully: Terraform will show a diff removing the inline block and adding the new resource, but this does not delete existing S3 lifecycle rules if configured correctly (verify with `terraform plan`).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/S3BucketLifecycle.json
- AWS docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html
