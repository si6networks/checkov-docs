# CKV2_AWS_6: Ensure that S3 bucket has a Public Access block

## Severity
**CRITICAL** (score: 9.1/10)

Absence of an S3 Public Access Block leaves the door open for a bucket (or a future bucket policy/ACL change) to become world-readable/writable, a top-tier root cause of large-scale AWS data breaches.

## Summary
This check requires every `aws_s3_bucket` to have a connected `aws_s3_bucket_public_access_block` resource with, at minimum, `block_public_acls = true` and `block_public_policy = true`.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_s3_bucket` (subject resource), `aws_s3_bucket_public_access_block` (must be connected to it)

## Why it matters
S3 data exposure via misconfigured public access remains one of the most common and damaging cloud misconfigurations, responsible for numerous large-scale breaches of PII, credentials, and internal documents. Without a Public Access Block, a bucket is only as safe as the discipline of every current and future ACL and bucket policy applied to it — a single mistaken `public-read` ACL, a permissive bucket policy added later, or a cross-account grant can instantly expose data to the entire internet. The Public Access Block is an account/bucket-level circuit breaker: even if an ACL or policy attempts to grant public access, S3 overrides it and blocks the grant, providing defense-in-depth against both current and future misconfiguration.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy) combining a connection requirement with attribute checks:
1. Filters to `aws_s3_bucket` resources.
2. Requires a graph **connection** to an `aws_s3_bucket_public_access_block` resource (i.e., a `aws_s3_bucket_public_access_block` whose `bucket` argument references this bucket).
3. On that connected `aws_s3_bucket_public_access_block` resource, requires `block_public_acls == true` **and** `block_public_policy == true`.

If the bucket has no connected public access block resource at all, or the connected resource doesn't set both `block_public_acls` and `block_public_policy` to `true`, the check **FAILS**. (Note: the check does not require `ignore_public_acls` or `restrict_public_buckets` to be `true`, though setting all four is the AWS-recommended full lockdown.)

## Non-compliant example
```hcl
resource "aws_s3_bucket" "reports" {
  bucket = "acme-internal-reports"
}
# No aws_s3_bucket_public_access_block resource at all -> FAILS
```

## Remediated example
```hcl
resource "aws_s3_bucket" "reports" {
  bucket = "acme-internal-reports"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true   # required by the check
  block_public_policy     = true   # required by the check
  ignore_public_acls      = true   # recommended, not required by this check
  restrict_public_buckets = true   # recommended, not required by this check
}
```

## Remediation steps
1. Add an `aws_s3_bucket_public_access_block` resource whose `bucket` attribute references the target bucket.
2. Set `block_public_acls = true` and `block_public_policy = true` at minimum to satisfy this specific check.
3. For full protection, also set `ignore_public_acls = true` and `restrict_public_buckets = true` — the check doesn't require these, but AWS and most security baselines (e.g., CIS AWS Foundations) recommend enabling all four.
4. If any legitimate public-read use case exists (e.g., static website hosting), scope the public access block per-bucket rather than omitting it, and consider CloudFront + OAC instead of direct public bucket access.
5. This is a Terraform-only, non-destructive addition — applying it does not require replacing the bucket.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/S3BucketHasPublicAccessBlock.json
- AWS docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
