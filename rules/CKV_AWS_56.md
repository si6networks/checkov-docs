# CKV_AWS_56: Ensure S3 bucket has 'restrict_public_buckets' enabled
## Severity
**MEDIUM** (score: 5.0/10)

Without RestrictPublicBuckets, cross-account or public principals can access the bucket even when other controls are misconfigured, directly enabling data exposure.

## Summary
This check verifies that an S3 bucket's Public Access Block configuration has `RestrictPublicBuckets` (CloudFormation) / `restrict_public_buckets` (Terraform) set to `true`, which restricts access to buckets/objects that have public bucket policies to only AWS services and authorized principals within the account.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::S3::Bucket` resources, property `Properties/PublicAccessBlockConfiguration/RestrictPublicBuckets`.
- **Terraform**: `aws_s3_bucket_public_access_block` resource, attribute `restrict_public_buckets`.

## Why it matters
Even when a bucket does end up with a public bucket policy (intentionally or via an oversight that `BlockPublicPolicy` didn't fully prevent, e.g. cross-account grants), `RestrictPublicBuckets` acts as a last line of defense: it overrides the public bucket policy so that only AWS services (like CloudFront) and account principals granted specific permissions can access the bucket — anonymous/public requests are blocked regardless of what the policy nominally allows. This matters especially for organizations that need to permit some public buckets by exception while ensuring the "default deny" posture holds for everything else, and it protects against policy drift over time (someone adds a broad `Principal: "*"` statement for a legitimate integration but forgets to scope it, and this setting prevents that mistake from becoming a public data exposure).

## How Checkov evaluates this
`BaseResourceValueCheck` — simple attribute check:
- Inspects `Properties/PublicAccessBlockConfiguration/RestrictPublicBuckets` for `AWS::S3::Bucket`.
- Inspects `restrict_public_buckets` for `aws_s3_bucket_public_access_block`.
- PASS: value is `true`.
- FAIL: value is `false`, or the attribute/block is missing.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "logs" {
  bucket = "app-access-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = false  # non-compliant
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "logs" {
  bucket = "app-access-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true   # fixed
}
```

## Remediation steps
1. Add or update the bucket's `aws_s3_bucket_public_access_block` (Terraform) / `PublicAccessBlockConfiguration` (CloudFormation).
2. Set `restrict_public_buckets` / `RestrictPublicBuckets` to `true`.
3. If the bucket is deliberately public (e.g., for static assets served without CloudFront), enabling this may break anonymous access — verify access patterns before enabling in production, or front the bucket with CloudFront + Origin Access Control instead of relying on a public bucket policy.
4. Pair with `block_public_acls`, `ignore_public_acls`, and `block_public_policy` (CKV_AWS_53/55/54) for the complete public-access-block posture.
5. Non-disruptive, in-place change.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/S3RestrictPublicBuckets.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3RestrictPublicBuckets.py)
- [AWS: Blocking public access to your S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
