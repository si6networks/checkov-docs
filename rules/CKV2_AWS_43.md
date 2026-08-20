# CKV2_AWS_43: Ensure S3 Bucket does not allow access to all Authenticated users
## Severity
**MEDIUM** (score: 5.0/10)

An S3 ACL granting access to the 'All Authenticated AWS Users' group exposes bucket objects to any AWS account holder worldwide, not just the bucket owner's intended principals.

## Summary
This check fails when an `aws_s3_bucket_acl` grants access to the `AuthenticatedUsers` predefined group, which is any AWS account holder worldwide — not just users within your own account or organization.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_s3_bucket_acl`

## Why it matters
The `http://acs.amazonaws.com/groups/global/AuthenticatedUsers` grantee URI is one of S3's legacy "predefined groups," and despite its name it does **not** mean "authenticated users in my AWS account." It means any principal holding valid AWS credentials anywhere — effectively any of the tens of millions of AWS accounts on the planet, since anyone can sign up for a free AWS account and immediately satisfy "authenticated." Granting `READ`, `WRITE`, or `READ_ACP`/`WRITE_ACP` to this group is functionally almost as dangerous as making the bucket public, but is easy to overlook during review because "AuthenticatedUsers" sounds restrictive. This misconfiguration has led to real-world data breaches where buckets thought to be private were in fact readable/writable by any AWS customer.

## How Checkov evaluates this
This is a graph-based JSON policy that inspects the ACL grants:
- **Attribute checked:** `access_control_policy.grant.*.grantee.uri` on `aws_s3_bucket_acl`
- **Operator:** `not_equals` against the value `http://acs.amazonaws.com/groups/global/AuthenticatedUsers`
- **PASS** if no grant's `grantee.uri` equals that global-authenticated-users group URI.
- **FAIL** if any grant in the ACL's grant list targets that URI, regardless of the specific permission (`READ`, `WRITE`, `FULL_CONTROL`, etc.) granted.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "example-data-bucket"
}

resource "aws_s3_bucket_acl" "bad" {
  bucket = aws_s3_bucket.data.id

  access_control_policy {
    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
      }
      permission = "READ"
    }

    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "example-data-bucket"
}

resource "aws_s3_bucket_acl" "good" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## Remediation steps
1. Remove any ACL grant targeting `http://acs.amazonaws.com/groups/global/AuthenticatedUsers` (and its sibling `AllUsers` group).
2. Prefer the canned `private` ACL, or migrate away from ACLs entirely toward bucket policies and IAM for access control (AWS now defaults new buckets to ACLs disabled / bucket owner enforced).
3. Attach an `aws_s3_bucket_public_access_block` resource with all four settings set to `true` as a defense-in-depth backstop.
4. If specific external accounts genuinely need access, grant it explicitly by AWS account canonical ID or via a scoped bucket policy — never via the `AuthenticatedUsers`/`AllUsers` predefined groups.
5. Audit existing objects/ACLs after remediation, since object-level ACLs can independently grant the same broad access even after the bucket ACL is fixed.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/S3NotAllowAccessToAllAuthenticatedUsers.json
- AWS docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#specifying-grantee
