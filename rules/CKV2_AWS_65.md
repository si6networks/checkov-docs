# CKV2_AWS_65: Ensure access control lists for S3 buckets are disabled

## Severity
**LOW** (score: 2.0/10)

Leaving S3 ACLs enabled (instead of enforcing bucket-owner-only access) retains a legacy access-control mechanism prone to misconfiguration that can grant unintended read/write access to objects, though it requires an additional ACL misstep to actually expose data.

## Summary
This check requires `aws_s3_bucket_ownership_controls` resources to set `rule.object_ownership` to `BucketOwnerEnforced`, which fully disables S3 ACLs on the bucket in favor of IAM/bucket-policy-only access control.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_s3_bucket_ownership_controls`

## Why it matters
S3 ACLs are a legacy, per-object/per-bucket access-control mechanism that is easy to misuse — a single `public-read` or `public-read-write` ACL grant (applied by a developer, an SDK default, or an automated upload tool) can expose objects to the entire internet independent of any bucket policy or IAM restriction, and ACL grants are notoriously hard to audit at scale since they can be set per-object rather than centrally. ACLs are also a common source of cross-account confusion: granting access to another AWS account via ACL (e.g., `grantee.id`) can silently give that account's canonical user ID read/write access outside of any reviewed IAM/bucket-policy change. `BucketOwnerEnforced` disables ACLs entirely, making the bucket owner the object owner for all objects regardless of who uploaded them and forcing all access control through auditable, centrally-reviewable IAM policies and bucket policies — eliminating an entire class of ACL-based misconfiguration and the S3 "confused ownership" problems that arise in cross-account setups.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy) with a single `attribute` condition:
- **Resource type:** `aws_s3_bucket_ownership_controls`
- **Attribute:** `rule.object_ownership`
- **Operator:** `equals`
- **Required value:** `"BucketOwnerEnforced"`

Any other value (`BucketOwnerPreferred`, `ObjectWriter`) or a missing `aws_s3_bucket_ownership_controls` resource altogether causes the check to **FAIL** (implicitly, since the required attribute/value won't be found).

## Non-compliant example
```hcl
resource "aws_s3_bucket" "assets" {
  bucket = "acme-static-assets"
}

resource "aws_s3_bucket_ownership_controls" "assets" {
  bucket = aws_s3_bucket.assets.id

  rule {
    object_ownership = "ObjectWriter"   # ACLs still active -> FAILS
  }
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "assets" {
  bucket = "acme-static-assets"
}

resource "aws_s3_bucket_ownership_controls" "assets" {
  bucket = aws_s3_bucket.assets.id

  rule {
    object_ownership = "BucketOwnerEnforced"  # ACLs disabled -> PASSES
  }
}
```

## Remediation steps
1. Add (or update) an `aws_s3_bucket_ownership_controls` resource for the bucket with `rule.object_ownership = "BucketOwnerEnforced"`.
2. Remove any `aws_s3_bucket_acl` resources and `acl` arguments elsewhere in configuration for this bucket — they become invalid once ACLs are disabled and will error at apply time.
3. Migrate any access previously granted via ACL (e.g., cross-account read grants) to equivalent bucket-policy statements before disabling ACLs, to avoid breaking legitimate access.
4. Note this has been the AWS default for new buckets created via the console since April 2023; explicitly setting it in Terraform ensures IaC-provisioned buckets match that secure default.
5. This is generally a safe, non-destructive change, but test thoroughly if any workload uploads objects with per-object ACLs (e.g., `public-read` on individual objects) — those grants stop functioning once `BucketOwnerEnforced` is set.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/AWSdisableS3ACL.json
- AWS docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html
