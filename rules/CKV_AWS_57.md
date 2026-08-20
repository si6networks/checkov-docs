# CKV_AWS_57: Ensure the S3 bucket does not allow WRITE permissions to everyone
## Severity
**HIGH** (score: 7.5/10)

An S3 bucket ACL granting WRITE to Everyone/AllUsers lets any unauthenticated internet user upload, overwrite, or delete objects, enabling data tampering, malware hosting, or destructive attacks.

## Summary
This check fails when an S3 bucket's ACL grants public WRITE (or FULL_CONTROL/WRITE_ACP) access — either via the canned `public-read-write` ACL or via an explicit grant to the `AllUsers` group — allowing anyone on the internet to upload, overwrite, or delete objects in the bucket.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::S3::Bucket`, property `Properties/AccessControl`.
- **Terraform**: graph-based check across `aws_s3_bucket` (attribute `acl`) and the separate `aws_s3_bucket_acl` resource (attributes `acl` and `access_control_policy.grant[*]`), since AWS provider v4+ moved ACL configuration out of `aws_s3_bucket` into its own resource.

## Why it matters
A bucket with public WRITE access lets any unauthenticated internet user upload arbitrary objects — this is a classic vector for hosting malware, planting phishing pages, injecting malicious content into a supply chain (e.g., overwriting a JS/config file an application trusts), or simply running up storage costs and legal exposure via abuse. FULL_CONTROL or WRITE_ACP grants are equally dangerous because they let an attacker also rewrite the object/bucket ACL itself, potentially escalating to read access or locking out the legitimate owner. Unlike a public-READ misconfiguration (data leakage), public WRITE is an active-compromise vector: it converts your bucket into infrastructure an attacker controls.

## How Checkov evaluates this
**CloudFormation** (`BaseResourceNegativeValueCheck`): inspects `Properties/AccessControl` on `AWS::S3::Bucket` — FAILS if the value equals the forbidden value `PublicReadWrite`; otherwise PASSES.

**Terraform** (graph-based JSON policy `S3PublicACLWrite.json`): evaluates several paths, PASSING (i.e., not vulnerable) when any of these hold:
- `aws_s3_bucket.acl` exists and is not `"public-read-write"`, OR
- an `aws_s3_bucket` is connected to an `aws_s3_bucket_acl` resource whose `acl` attribute exists and is not `"public-read-write"`, OR
- the connected `aws_s3_bucket_acl` instead uses `access_control_policy` with explicit `grant` blocks, and none of those grants both target the `AllUsers` group URI (`http://acs.amazonaws.com/groups/global/AllUsers`) AND grant `WRITE`, `FULL_CONTROL`, or `WRITE_ACP` permission, OR
- the `aws_s3_bucket` has no `acl` attribute and no connected `aws_s3_bucket_acl` at all (nothing configured -> default private ACL, considered compliant).
It FAILS when a grant to `AllUsers` with `WRITE`/`FULL_CONTROL`/`WRITE_ACP` is found, or when the canned ACL is literally `public-read-write`.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "public_uploads" {
  bucket = "public-uploads-bucket"
}

resource "aws_s3_bucket_acl" "public_uploads" {
  bucket = aws_s3_bucket.public_uploads.id
  acl    = "public-read-write"   # non-compliant
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "public_uploads" {
  bucket = "public-uploads-bucket"
}

resource "aws_s3_bucket_acl" "public_uploads" {
  bucket = aws_s3_bucket.public_uploads.id
  acl    = "private"            # fixed
}
```

## Remediation steps
1. Never use the canned ACLs `public-read-write` (or grant `WRITE`/`FULL_CONTROL`/`WRITE_ACP` to the `AllUsers`/`AuthenticatedUsers` groups).
2. Set `acl = "private"` (the default) on `aws_s3_bucket_acl`, or omit ACL configuration entirely and rely on bucket policy + IAM for access control (recommended for AWS provider v4+, where "Object Ownership" with `BucketOwnerEnforced` disables ACLs altogether).
3. Grant write access to specific IAM principals via a bucket policy or IAM policy instead of a public ACL.
4. Also enable the S3 Block Public Access settings (CKV_AWS_53/54/55/56) so that even a future accidental public ACL/policy has no effect.
5. If pre-signed URLs are needed for external upload workflows, use time-limited, scoped presigned PUT URLs rather than a public ACL.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/S3PublicACLWrite.py)
- [Checkov check source (Terraform, graph check)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/S3PublicACLWrite.json)
- [AWS: Access control list (ACL) overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html)
