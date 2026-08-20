# CKV_AWS_375: Ensure AWS S3 bucket does not have global view ACL permissions enabled

## Severity
**LOW** (score: 2.0/10)

Granting FULL_CONTROL or READ_ACP to the AllUsers group hands anonymous internet users the ability to read, overwrite, delete, or reconfigure permissions on the bucket, directly enabling mass data exfiltration or defacement.

## Summary
This check flags an S3 bucket ACL that grants the `AllUsers` group (i.e., the entire internet) `FULL_CONTROL` or `READ_ACP` permission, which would let anyone read the bucket's access-control configuration or fully control the bucket.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_s3_bucket_acl`

## Why it matters
S3 ACL grants use predefined groups, and `http://acs.amazonaws.com/groups/global/AllUsers` represents anonymous, unauthenticated access from anyone on the internet. Granting this group:

- `READ_ACP` — lets any anonymous user read the bucket's ACL, revealing exactly who else has access and what permissions they hold. This is reconnaissance information that helps an attacker plan further exploitation (e.g., identifying which accounts/roles to target or impersonate).
- `FULL_CONTROL` — is far worse, since it is equivalent to granting `READ`, `WRITE`, `READ_ACP`, and `WRITE_ACP` to the entire internet, i.e., anyone can read, overwrite, delete, or reconfigure permissions on the bucket, potentially leading to full data exfiltration, defacement, or ransom.

This is exactly the class of misconfiguration behind numerous public S3 data-exposure incidents.

## How Checkov evaluates this
The check inspects `access_control_policy[].grant[]` blocks in the `aws_s3_bucket_acl` resource. For each grant, it looks at `permission` — if the permission list contains `FULL_CONTROL` or `READ_ACP` — and then examines the corresponding `grantee` block(s). If any grantee's `uri` equals `http://acs.amazonaws.com/groups/global/AllUsers`, the check **FAILS**. If no grant matches this pattern (or no `access_control_policy`/`grant` block exists at all), the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "example-bucket"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id

  access_control_policy {
    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/global/AllUsers"
      }
      permission = "FULL_CONTROL"
    }

    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
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
```

## Remediation steps
1. Remove any `grant` block in `access_control_policy` whose `grantee.uri` targets the `AllUsers` (or `AuthenticatedUsers`) canonical group with `FULL_CONTROL` or `READ_ACP` permission.
2. Prefer the simple `acl = "private"` argument on `aws_s3_bucket_acl` instead of hand-crafting `access_control_policy` grants, unless you have a specific, narrowly scoped need (e.g., static website hosting via CloudFront OAC, not public ACLs).
3. Pair this with an `aws_s3_bucket_public_access_block` resource (with `block_public_acls`, `ignore_public_acls`, `block_public_policy`, `restrict_public_buckets` all `true`) to prevent public ACLs from being applied even if reintroduced later.
4. If public read access is truly required (e.g., serving static assets), use a bucket policy scoped to specific actions (like `s3:GetObject`) rather than ACL-based `FULL_CONTROL`/`READ_ACP` to the `AllUsers` group, and consider fronting the bucket with CloudFront instead of direct public bucket access.
5. Applying this change does not require resource replacement, but will alter public access to existing objects immediately — verify nothing depends on the current public grant before removing it.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3GlobalViewACL.py)
- [AWS S3 access control list (ACL) overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html)
