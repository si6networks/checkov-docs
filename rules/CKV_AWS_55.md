# CKV_AWS_55: Ensure S3 bucket has ignore public ACLs enabled
## Severity
**MEDIUM** (score: 5.0/10)

Without IgnorePublicAcls, legacy or accidental public ACL grants on objects/buckets are honored, allowing unauthorized public read/write access to stored data.

## Summary
This check verifies that an S3 bucket's Public Access Block configuration has `IgnorePublicAcls` (CloudFormation) / `ignore_public_acls` (Terraform) set to `true`, so that any public ACL granted on the bucket or its objects is ignored by S3.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::S3::Bucket` resources, property `Properties/PublicAccessBlockConfiguration/IgnorePublicAcls`.
- **Terraform**: `aws_s3_bucket_public_access_block` resource, attribute `ignore_public_acls`.

## Why it matters
S3 Access Control Lists (ACLs) are a legacy, per-object/per-bucket access mechanism that predates IAM/bucket policies, and they are notoriously easy to misconfigure — e.g., an application uploading objects with `public-read` ACL by default, or a script that calls `PutBucketAcl`/`PutObjectAcl` with the `AllUsers` or `AuthenticatedUsers` grantee group. Because ACLs act independently of and in addition to IAM/bucket policy, a restrictive bucket policy alone does not protect against a permissive ACL. `IgnorePublicAcls` closes this gap: when enabled, S3 disregards any ACL that grants public access, so even if an ACL is (mis)configured to be public, it has no effect. This is a critical guardrail for buckets that receive user- or application-uploaded content, where ACLs are often set programmatically and are easy to get wrong.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (simple attribute check):
- Inspects `Properties/PublicAccessBlockConfiguration/IgnorePublicAcls` for `AWS::S3::Bucket`.
- Inspects `ignore_public_acls` for `aws_s3_bucket_public_access_block`.
- PASS: value is `true`.
- FAIL: value is `false` or the attribute/block is absent.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "user-uploads-bucket"
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  block_public_acls       = true
  ignore_public_acls      = false  # non-compliant
  block_public_policy     = true
  restrict_public_buckets = true
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "user-uploads-bucket"
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  block_public_acls       = true
  ignore_public_acls      = true   # fixed
  block_public_policy     = true
  restrict_public_buckets = true
}
```

## Remediation steps
1. Add or update the `aws_s3_bucket_public_access_block` (Terraform) / `PublicAccessBlockConfiguration` (CloudFormation) attached to the bucket.
2. Set `ignore_public_acls` / `IgnorePublicAcls` to `true`.
3. Migrate any application logic that relies on setting object ACLs (e.g., `public-read`) to use pre-signed URLs, CloudFront with Origin Access Control, or bucket-policy-based access instead — once this setting is enabled those ACLs will simply be ignored, which can break workflows that depended on them for public access.
4. Combine with `block_public_acls`, `block_public_policy`, and `restrict_public_buckets` for complete protection (CKV_AWS_53/54/56).
5. This is a non-disruptive, in-place change; no resource replacement needed.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/S3IgnorePublicACLs.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3IgnorePublicACLs.py)
- [AWS: Blocking public access to your S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
