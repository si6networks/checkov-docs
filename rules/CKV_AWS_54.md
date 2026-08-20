# CKV_AWS_54: Ensure S3 bucket has block public policy enabled
## Severity
**MEDIUM** (score: 5.0/10)

Without BlockPublicPolicy, a single overly-permissive bucket policy statement takes effect immediately and can expose the bucket's entire contents to the public internet.

## Summary
This check verifies that an S3 bucket's Public Access Block configuration has `BlockPublicPolicy` (CloudFormation) / `block_public_policy` (Terraform) set to `true`, preventing bucket policies that grant public access from taking effect.

## Applicability
- **CloudFormation**: `AWS::S3::Bucket` resources (specifically the `Properties/PublicAccessBlockConfiguration/BlockPublicPolicy` property).
- **Terraform**: `aws_s3_bucket_public_access_block` resource, attribute `block_public_policy`.

## Why it matters
S3 bucket policies are one of the most common ways buckets end up unintentionally exposed to the internet — a single overly-broad `Principal: "*"` statement or a misconfigured cross-account condition in a bucket policy can make an entire bucket world-readable or world-writable. `BlockPublicPolicy` is an account/bucket-level guardrail that Amazon S3 enforces independently of the bucket policy's own logic: when enabled, S3 will reject (or ignore) any bucket policy that grants public access, regardless of what the policy document actually says. This gives defense-in-depth against a developer or CI pipeline accidentally publishing a public-access policy, and against future edits to the policy silently re-opening the bucket. Without this setting, a bad bucket policy change is immediately effective and can cause data exposure or, for buckets holding executable artifacts/config, third-party tampering.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`, which is a simple attribute-presence/value check (no branching logic beyond that base class):
- It inspects `Properties/PublicAccessBlockConfiguration/BlockPublicPolicy` for `AWS::S3::Bucket` (CloudFormation).
- It inspects `block_public_policy` for `aws_s3_bucket_public_access_block` (Terraform).
- PASS: the value is explicitly `true`.
- FAIL: the value is `false`, or the key/block is missing entirely (default value check treats missing config as non-compliant).

## Non-compliant example
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-app-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = false   # non-compliant
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-app-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true    # fixed
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## Remediation steps
1. Attach an `aws_s3_bucket_public_access_block` resource (Terraform) or a `PublicAccessBlockConfiguration` property block (CloudFormation) to every S3 bucket.
2. Set `block_public_policy` / `BlockPublicPolicy` to `true`.
3. While you're there, also set `block_public_acls`, `ignore_public_acls`, and `restrict_public_buckets` to `true` (see CKV_AWS_53/55/56) — these four settings work together as the full "Block Public Access" feature set.
4. If a bucket genuinely needs to be public (e.g., static website hosting, public downloads), do not disable this globally — instead scope public access narrowly via a bucket policy condition and document the exception, since this setting will actively block any conflicting public bucket policy.
5. No resource replacement is required; this is a non-disruptive, in-place update.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/S3BlockPublicPolicy.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3BlockPublicPolicy.py)
- [AWS: Blocking public access to your S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
