# CKV_AWS_20: Ensure the S3 bucket does not allow READ permissions to everyone
## Severity
**HIGH** (score: 7.5/10)

An S3 bucket ACL granting READ to everyone makes bucket contents world-readable over the internet, a common and severe real-world cause of sensitive data exposure and breach.

## Summary
Ensures an S3 bucket's ACL is not set to a canned ACL that grants read access to all users (`public-read` or `public-read-write`), which would let anyone on the internet list/read bucket objects.

## Applicability
- **CloudFormation**: `AWS::S3::Bucket` — inspects `Properties/AccessControl`; fails if it equals `PublicRead` or `PublicReadWrite`.
- **Terraform** (graph-based check): `aws_s3_bucket` (legacy inline `acl` attribute) and the separate `aws_s3_bucket_acl` resource (AWS provider v4+ split resource model), including its `access_control_policy.grant[].grantee.uri` grants.

## Why it matters
An S3 bucket ACL of `public-read` or `public-read-write` grants the special `AllUsers` group (anyone on the internet, unauthenticated) permission to list and read every object in the bucket. This is one of the most common and highest-impact cloud misconfigurations, historically responsible for numerous large-scale data breaches involving customer PII, credentials, internal source code, and backups. Beyond direct data exposure:
- `public-read-write` additionally allows anonymous users to *overwrite or delete* objects, enabling defacement, ransomware-style destruction, or supply-chain-style injection of malicious files served from a trusted domain.
- Search engines, scanners, and automated bots continuously enumerate S3 bucket names, meaning any accidentally public bucket is discovered quickly, not hypothetically.

## How Checkov evaluates this
- **CloudFormation** (`BaseResourceNegativeValueCheck`): fails if `Properties/AccessControl` equals `PublicRead` or `PublicReadWrite`; any other value (or absence) passes.
- **Terraform** (graph check, JSON policy): passes if either:
  - the `aws_s3_bucket.acl` attribute exists and is NOT one of `public-read`, `public-read-write`, `website`, `authenticated-read`; OR
  - the bucket has a connected `aws_s3_bucket_acl` resource whose `acl` attribute is not one of those same forbidden values, AND (if it uses raw grants via `access_control_policy`) none of its `access_control_policy.grant[].grantee.uri` equals `http://acs.amazonaws.com/groups/global/AllUsers`; OR
  - the bucket has neither an inline `acl` nor a connected `aws_s3_bucket_acl` at all (defaults to private).
  It fails when the bucket (or its associated `aws_s3_bucket_acl`) explicitly sets one of the forbidden canned ACLs, or grants the `AllUsers` group access via a custom grant.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "reports" {
  bucket = "company-quarterly-reports"
}

resource "aws_s3_bucket_acl" "reports_acl" {
  bucket = aws_s3_bucket.reports.id
  acl    = "public-read"   # FAILS CKV_AWS_20
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "reports" {
  bucket = "company-quarterly-reports"
}

resource "aws_s3_bucket_acl" "reports_acl" {
  bucket = aws_s3_bucket.reports.id
  acl    = "private"   # fix: no public grant
}

resource "aws_s3_bucket_public_access_block" "reports_pab" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## Remediation steps
1. Set the bucket's ACL (either inline `acl` on `aws_s3_bucket` for AWS provider < v4, or the dedicated `aws_s3_bucket_acl` resource for v4+) to `private`.
2. Remove any custom grants in `access_control_policy` targeting the `http://acs.amazonaws.com/groups/global/AllUsers` or `AuthenticatedUsers` group URIs.
3. Add an `aws_s3_bucket_public_access_block` resource with all four blocking options set to `true` as defense in depth, even if ACLs are already private — this prevents future accidental re-exposure via bucket policy or ACL changes.
4. If the bucket genuinely needs to serve public content (e.g., static website assets), use a scoped bucket policy for specific prefixes plus CloudFront + Origin Access Control instead of a blanket public ACL, and consider suppressing this check with a documented justification only for that specific bucket.
5. After changing ACLs on a bucket with existing objects, note that object-level ACLs may also need updating if they were individually set to public.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/S3PublicACLRead.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/S3PublicACLRead.json
- AWS docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
