# CKV_AWS_392: Ensure AWS S3 access point block public access setting is enabled
## Severity
**HIGH** (score: 7.8/10)

An S3 access point with public access blocking disabled can expose the underlying bucket's objects to anonymous internet access, risking disclosure of potentially sensitive data.

## Summary
This check ensures that an S3 Access Point's `public_access_block_configuration` does not have all four block-public-access controls simultaneously disabled, which would allow the access point to serve public requests to the underlying bucket.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_s3_access_point`

## Why it matters
S3 Access Points are named network endpoints attached to a bucket with their own access policy, and they have their own independent public-access-block settings layered on top of (or separate from) the bucket's own block-public-access configuration. If an access point's block-public-access settings are all turned off (`block_public_acls`, `block_public_policy`, `restrict_public_buckets` all `false`), the access point can potentially expose bucket objects to anonymous or cross-account access even if the underlying bucket itself is otherwise locked down — because access points can carry their own permissive policy. This is a common blind spot: teams harden the bucket's public access block but forget that each access point has its own toggle, effectively creating a bypass.

## How Checkov evaluates this
The check is a `BaseResourceCheck` against `aws_s3_access_point`. It inspects the `public_access_block_configuration` block:
- If the block exists and **all three** of `block_public_acls`, `block_public_policy`, and `restrict_public_buckets` are explicitly present and set to `false` → **FAIL**.
- Otherwise (block absent, or any one of the three settings is `true`/not `false`) → **PASS**.

Note: the source code checks for the key `ignore_public_acls` in the condition alongside `block_public_acls`, but only evaluates the boolean values of `block_public_acls`, `block_public_policy`, and `restrict_public_buckets`. In practice, the check fails only when all three of those are explicitly `false`.

## Non-compliant example
```hcl
resource "aws_s3_access_point" "example" {
  bucket = aws_s3_bucket.data.id
  name   = "example-access-point"

  public_access_block_configuration {
    block_public_acls       = false
    block_public_policy     = false
    ignore_public_acls      = false
    restrict_public_buckets = false
  }
}
```

## Remediated example
```hcl
resource "aws_s3_access_point" "example" {
  bucket = aws_s3_bucket.data.id
  name   = "example-access-point"

  public_access_block_configuration {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}
```

## Remediation steps
1. Set `block_public_acls`, `block_public_policy`, and `restrict_public_buckets` (and `ignore_public_acls`) to `true` in the access point's `public_access_block_configuration` block.
2. If the access point genuinely needs to serve public content (rare), scope the exception narrowly and document the business justification, and consider using a CloudFront distribution with origin access control instead of exposing the access point directly.
3. Audit all existing access points on sensitive buckets — this setting is easy to miss because it's independent from the bucket-level `aws_s3_bucket_public_access_block`.
4. Re-run `checkov` to confirm compliance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3AccessPointPubliclyAccessible.py)
- [AWS S3 Access Points documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points.html)
