# CKV_AWS_70: Ensure S3 bucket does not allow an action with any Principal
## Severity
**MEDIUM** (score: 5.0/10)

An S3 bucket policy that allows an action for any Principal (a wildcard "*" principal without a restrictive condition) can grant anonymous/public access to bucket data or operations, which is a classic root cause of large-scale S3 data exposures.

## Summary
This check fails when an S3 bucket policy grants access to `Principal: "*"` (or `Principal.AWS: "*"`) without a condition clause that meaningfully restricts who `*` actually resolves to, effectively flagging S3 bucket policies that are open to any AWS principal (or the public).

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_s3_bucket` (inline `policy` argument), `aws_s3_bucket_policy`
- **Check type:** resource

## Why it matters
An S3 bucket policy statement with `"Principal": "*"` and `"Effect": "Allow"` grants the permitted action(s) to literally any AWS account or, if the bucket is not otherwise restricted, the anonymous/public internet. This is one of the most common causes of real-world S3 data breaches: a bucket that appears to have a "policy" in place can still be fully public if the policy's Principal is unconstrained. Even when paired with a `Condition` block, weak or overly broad conditions (e.g., an `ArnLike` condition matching `arn:aws:iam::*` for all accounts) don't meaningfully narrow the effective allowed principals and still expose the bucket to any external account satisfying the loose condition. Overly permissive bucket policies undermine defense-in-depth even when Block Public Access or bucket ACLs are otherwise configured correctly, and are frequently the root cause reported in cloud security incident post-mortems.

## How Checkov evaluates this
The check (`S3AllowsAnyPrincipal.py`) inspects the resource's `policy` attribute:
1. If `policy` is absent, result is `UNKNOWN`.
2. If the policy references `data.aws_iam_policy_document` (a separate Terraform data source Checkov can't statically resolve), result is `UNKNOWN`.
3. Otherwise the policy JSON string is parsed. For each `Statement` where `Effect` is not `Deny` and a `Principal` key exists:
   - If `Principal == "*"` or `Principal.AWS` is (or contains) `"*"`, the check calls `check_conditions()`.
4. `check_conditions()` inspects the statement's `Condition` block:
   - No `Condition` at all → **FAIL**.
   - `ArnNotEquals` / `ArnNotLike` present → treated as sufficiently restrictive → **PASS**.
   - `ArnEquals` / `ArnLike` present with `aws:PrincipalArn` or `aws:SourceArn`: if that ARN pattern matches a wildcard covering an entire account/service (regex `^arn:aws:[a-z0-9-]+::\*.*$`) → **FAIL**; otherwise → **PASS**.
   - `StringEquals` / `StringEqualsIgnoreCase` / `StringLike` present with a recognized narrowing key (e.g. `aws:SourceVpce`, `aws:PrincipalOrgID`, `aws:PrincipalAccount`, `ec2:SourceInstanceArn`, etc.) → **PASS**.
   - Otherwise → **FAIL** (default).
5. If no statement has `Principal: "*"`, the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "example-data-bucket"
}

resource "aws_s3_bucket_policy" "data_policy" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.data.arn}/*"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "example-data-bucket"
}

resource "aws_s3_bucket_policy" "data_policy" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSpecificAccountOnly"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.data.arn}/*"
        Condition = {
          StringEquals = {
            "aws:PrincipalAccount" = "123456789012"
          }
        }
      }
    ]
  })
}
```

## Remediation steps
1. Replace `Principal: "*"` with a specific principal (AWS account ARN, IAM role ARN, or AWS service principal) wherever possible.
2. If a wildcard principal is truly required (e.g., for a CloudFront OAC/OAI pattern or public static website), add a `Condition` block that narrows access using a specific, non-wildcard key such as `aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:SourceArn`, or `aws:SourceVpce` — avoid conditions that still match "any ARN in any account."
3. Never use `ArnLike`/`ArnEquals` conditions with account-level wildcards (`arn:aws:iam::*:*`), as these are treated as unrestrictive.
4. Pair the bucket policy with S3 Block Public Access settings (`aws_s3_bucket_public_access_block`) as defense-in-depth.
5. If the policy is built via `data.aws_iam_policy_document`, Checkov cannot statically evaluate it (result is `UNKNOWN`) — manually review such policies for the same wildcard-principal risk.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3AllowsAnyPrincipal.py)
- [AWS S3 bucket policy examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
