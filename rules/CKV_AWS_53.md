# CKV_AWS_53: Ensure S3 bucket has block public ACLs enabled
## Severity
**MEDIUM** (score: 5.0/10)

Disabling S3's block-public-ACLs setting allows bucket or object ACLs to grant public access, a common root cause of large-scale accidental exposure of stored data to the internet.

## Summary
This check ensures that the S3 bucket-level (or account-level) public access block configuration has `BlockPublicAcls` enabled, preventing new public ACLs from being applied to the bucket or its objects.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::S3::Bucket` (CloudFormation, inspecting `Properties/PublicAccessBlockConfiguration/BlockPublicAcls`); `aws_s3_bucket_public_access_block` (Terraform, inspecting `block_public_acls`)

## Why it matters
S3 bucket and object ACLs are a legacy access-control mechanism that predates bucket policies and IAM, and they are a frequent source of accidental public exposure — a developer applying `public-read` ACL to an object for a quick test, a misconfigured upload client setting a public ACL by default, or a third-party tool defaulting to permissive ACLs. `BlockPublicAcls` acts as a preventive guardrail: when enabled, S3 rejects PUT requests that attempt to set a public ACL on the bucket or its objects, regardless of what any individual bucket policy or IAM permission would otherwise allow. Without it, a single mistaken ACL grant (`AllUsers` read/write) can expose bucket contents — or make them writable — to the entire internet, which has been the root cause of numerous large-scale public data-exposure incidents. This is one of four related "block public access" settings (the others govern existing public ACLs, bucket policies, and cross-account access) and is typically enabled together with its siblings.

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck`:
- **CloudFormation:** inspects `Properties/PublicAccessBlockConfiguration/BlockPublicAcls` on `AWS::S3::Bucket` — **PASS** if `true`, **FAIL** if `false` or absent.
- **Terraform:** inspects the `block_public_acls` argument on the separate `aws_s3_bucket_public_access_block` resource — **PASS** if `true`, **FAIL** if `false` or absent.

Note: in modern Terraform AWS provider versions, public access block settings are configured via the standalone `aws_s3_bucket_public_access_block` resource associated with a bucket (not inline in `aws_s3_bucket`), so this resource must exist and be correctly attached to the bucket for the setting to take effect at all.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "example-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "example-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## Remediation steps
1. Ensure every bucket has an associated `aws_s3_bucket_public_access_block` resource, and set `block_public_acls = true` on it.
2. Also set the sibling attributes (`block_public_policy`, `ignore_public_acls`, `restrict_public_buckets`) to `true` unless there's a specific, documented reason a bucket needs to remain publicly accessible (e.g., static website hosting, and even then prefer serving via CloudFront with origin access control instead of a public bucket).
3. Audit existing bucket ACLs before enabling this setting — if any existing objects rely on public ACLs, they will not be retroactively affected by `BlockPublicAcls` alone (see `ignore_public_acls` for handling existing grants), so plan the rollout of all four settings together.
4. Consider enabling S3 Block Public Access at the **account level** (via `aws_s3_account_public_access_block`) as a stronger, org-wide guardrail that can't be bypassed by an individual bucket's configuration.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3BlockPublicACLs.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/S3BlockPublicACLs.py)
- [AWS S3 Block Public Access documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
