# CKV_AWS_300: Ensure S3 lifecycle configuration sets period for aborting failed uploads
## Severity
**MEDIUM** (score: 5.0/10)

This check verifies S3 lifecycle rules abort incomplete multipart uploads; missing it is purely a cost/storage-hygiene issue with no direct confidentiality, integrity, or access-control impact.

## Summary
This check ensures an `aws_s3_bucket_lifecycle_configuration` resource includes an enabled rule with `abort_incomplete_multipart_upload` configured (and, if a filter is present, that filter must be empty/unscoped so the rule applies broadly) — otherwise incomplete multipart uploads can accumulate indefinitely and incur storage costs.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_s3_bucket_lifecycle_configuration`

## Why it matters
While framed primarily as a cost/hygiene control, this check has real security relevance: incomplete multipart uploads that are never aborted or cleaned up sit in the bucket as invisible, non-listed storage that still consumes space and (depending on tooling) may not appear in normal object listings, making it a poor place for data to silently accumulate without governance, retention, or access review. From a pure reliability/cost standpoint, S3 bills for storage consumed by incomplete multipart upload parts even though they're not visible as regular objects — an attacker or a buggy client repeatedly initiating multipart uploads that never complete (intentionally or as a denial-of-wallet attack) can drive costs up indefinitely if there's no automatic abort policy. This is categorized by Checkov as `GENERAL_SECURITY` because ungoverned, unbounded storage growth undermines both cost control and the completeness of security/data-inventory processes that assume all stored data is enumerable via standard object listings.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` (Python check). For each `rule` block:
- It requires `abort_incomplete_multipart_upload` to be present AND `status == "Enabled"`.
- If the rule additionally has a `filter` block, the check inspects the filter's conditions (`prefix`, `object_size_greater_than`, `object_size_less_than`, `tag`, including nested `and` conditions). If **any** of these filter conditions are non-empty, the rule is considered scoped to only part of the bucket and does **not** satisfy the check for that rule (it keeps searching other rules).
- An empty/absent filter means the rule applies bucket-wide, which **passes**.
- **PASS** if at least one enabled rule has `abort_incomplete_multipart_upload` configured with no (or an empty) filter.
- **FAIL** if no rule satisfies this (e.g., no lifecycle rules at all, rules present but not enabled, no `abort_incomplete_multipart_upload` block, or the only qualifying rules are scoped down via a non-empty filter).

## Non-compliant example
```hcl
resource "aws_s3_bucket_lifecycle_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    id     = "expire-old-objects"
    status = "Enabled"

    expiration {
      days = 365
    }
    # no abort_incomplete_multipart_upload block -> check FAILS
  }
}
```

## Remediated example
```hcl
resource "aws_s3_bucket_lifecycle_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7   # clean up stale multipart uploads
    }
  }

  rule {
    id     = "expire-old-objects"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}
```

## Remediation steps
1. Add a dedicated `rule` block to your `aws_s3_bucket_lifecycle_configuration` containing an `abort_incomplete_multipart_upload { days_after_initiation = N }` block, with `status = "Enabled"`.
2. Leave the `filter` block empty (or omit it) on this rule so it applies bucket-wide; if you need it scoped, add a separate unscoped rule dedicated solely to aborting incomplete uploads to still satisfy the check.
3. Choose a reasonable `days_after_initiation` value (commonly 1–7 days) based on how long legitimate large uploads might take to complete/retry.
4. Verify no existing rule with the same purpose is disabled (`status = "Disabled"`), which would not satisfy the check even if otherwise configured correctly.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3AbortIncompleteUploads.py)
