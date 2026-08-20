# CKV_AWS_379: Ensure AWS S3 bucket is configured with secure data transport policy

## Severity
**HIGH** (score: 7.5/10)

Without an enforced secure-transport (aws:SecureTransport) condition, an S3 bucket accepts unencrypted HTTP requests, allowing data in transit to and from the bucket to be intercepted or tampered with.

## Summary
This check ensures that an S3 bucket which is effectively public (via a public ACL or a public-access-block that does not restrict it) is not left without protection — specifically, it evaluates whether a publicly readable bucket is legitimately serving as a static website, otherwise it is treated as an unintended public exposure.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_s3_bucket_acl` (graph-aware: correlates with connected `aws_s3_bucket_public_access_block` and `aws_s3_bucket_website_configuration` resources)

## Why it matters
An S3 bucket ACL set to `public-read` or `public-read-write`, or containing an explicit grant to the `AllUsers` group, exposes bucket contents to anyone on the internet. This is only appropriate for a small set of legitimate use cases (e.g., static website hosting) — in every other case it is a data-exposure risk:

- Anonymous actors can enumerate and download every object in the bucket (`public-read`), or even upload/overwrite/delete objects (`public-read-write`), leading to data leakage, defacement, or malware hosting.
- A connected `aws_s3_bucket_public_access_block` that does not set `restrict_public_buckets`/`block_public_acls` fails to neutralize the exposure even if it exists, giving a false sense of security.
- The check specifically carves out an exception for buckets that are intentionally configured with `aws_s3_bucket_website_configuration`, since static website hosting requires public read access by design — but any other publicly-ACL'd bucket without that legitimate justification is flagged.

## How Checkov evaluates this
The check inspects the `aws_s3_bucket_acl` resource's `acl` attribute and `access_control_policy` grants:

1. If `acl` is `public-read` or `public-read-write`, it looks up the bucket ID and searches the Terraform graph for a connected `aws_s3_bucket_public_access_block` resource for the same bucket.
   - If no such block exists, the bucket is treated as public (`is_public = True`).
   - If one exists but neither `restrict_public_buckets` nor `block_public_acls` is set, it is also treated as public.
2. Independently, if `access_control_policy.grant[].grantee.uri` includes the `AllUsers` group URI, the same public-access-block lookup/logic is applied (checking `block_public_acls` this time) to determine if the ACL grant is actually neutralized.
3. If the bucket is not deemed public by either path, the check **PASSES**.
4. If it is deemed public, the check then looks for a connected `aws_s3_bucket_website_configuration` resource — if present, this legitimizes the public access (static website hosting) and the check **PASSES**; if absent, it **FAILS** (unjustified public exposure).

## Non-compliant example
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "example-bucket"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "public-read"
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "example-bucket"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

Or, if public access is genuinely required for static website hosting:

```hcl
resource "aws_s3_bucket" "example" {
  bucket = "example-bucket"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "public-read"
}

resource "aws_s3_bucket_website_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  index_document {
    suffix = "index.html"
  }
}
```

## Remediation steps
1. Set the bucket ACL to `private` unless the bucket is intentionally a static website.
2. Attach an `aws_s3_bucket_public_access_block` resource with all four settings (`block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets`) set to `true` for any bucket that should not be public.
3. If public read access is required, prefer scoping access via a bucket policy plus CloudFront Origin Access Control rather than a broad `public-read` ACL, and explicitly add an `aws_s3_bucket_website_configuration` resource so the intent is documented and Checkov recognizes the legitimate use case.
4. Audit any existing bucket with `public-read`/`public-read-write` ACLs to confirm the public exposure is intentional and currently justified.
5. No resource replacement is required; ACL and public-access-block changes apply in place, but verify no client depends on the current unauthenticated access before restricting it.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3SecureDataTransport.py)
- [AWS S3 block public access documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
