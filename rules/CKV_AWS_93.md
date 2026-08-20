# CKV_AWS_93: Ensure S3 bucket policy does not lockout all but root user

## Severity
**MEDIUM** (score: 5.0/10)

A bucket policy that locks out all principals but the root account can remove legitimate administrative access to the bucket, forcing risky root-account recovery and potentially leaving the bucket's own access controls unmanageable during an incident.

## Summary
This check fails when an S3 bucket policy contains a `Deny` statement, with no `Condition` and no `NotAction`, whose `Principal` is `*` (everyone) and whose `Action` covers broad S3 write/management permissions (e.g. `s3:*`, `s3:Put*`, `s3:*BucketPolicy`, `s3:PutBucketPolicy`, or `*`) — a pattern that can lock every IAM identity, including the ones who need to fix the policy, out of managing the bucket.

## Applicability
- **Terraform**: `aws_s3_bucket` (inline `policy` attribute) and `aws_s3_bucket_policy` resources — inspects the parsed JSON `policy` document's `Statement` list.

## Why it matters
S3 bucket policies are evaluated for every principal, including the AWS account root user and any IAM admin roles, unless the policy specifically carves out an exception. A broadly-scoped `Deny` statement (principal `*`, action `s3:*` or similar, no `Condition` to narrow it) denies the ability to modify the bucket policy to *everyone*, including the account owner. Once such a policy is applied, there is no IAM permission that can override an explicit S3 bucket-policy `Deny` — the only way out is to open an AWS Support case for a root-cause fix, which can mean extended downtime or total loss of control over the bucket. This is a classic "self-inflicted lockout" failure mode, distinct from most security misconfigurations in that it causes an availability/operational incident rather than a data-exposure incident — but it is severe because there is no self-service recovery path.

## How Checkov evaluates this
The check parses the `policy` argument (must be a JSON object, not an unresolved string) and iterates `Statement` entries:
- Statements are skipped (not evaluated) if they contain a `Condition` key, a `NotAction` key, or if `Effect` is not `"Deny"` — these are considered safe because a condition or NotAction typically scopes the deny narrowly.
- For remaining (unconditional, `Deny`) statements, it resolves the `Principal`: if `Principal.AWS` is the literal string `"*"` or a list containing `"*"`, the principal is treated as wildcard (`*`).
- If principal is `*`: if `Action == "*"` → **FAILED** immediately. Otherwise, each action in the (possibly list-valued) `Action` field is checked against the forbidden set `["s3:PutBucketPolicy", "s3:*BucketPolicy", "s3:Put*", "s3:*", "*"]`; a match → **FAILED**.
- If the `policy` key is absent, or any exception occurs while parsing, the check defaults to **PASSED** (fails open, since a malformed/unparseable policy can't be confidently flagged).

## Non-compliant example
```hcl
resource "aws_s3_bucket_policy" "lockout" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyAllPolicyChanges"
        Effect    = "Deny"
        Principal = { "AWS" : "*" }
        Action    = "s3:PutBucketPolicy"
        Resource  = aws_s3_bucket.data.arn
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_s3_bucket_policy" "safe" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyPolicyChangesExceptAdminRole"
        Effect    = "Deny"
        Principal = { "AWS" : "*" }
        Action    = "s3:PutBucketPolicy"
        Resource  = aws_s3_bucket.data.arn
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = "arn:aws:iam::123456789012:role/BucketAdminRole"
          }
        }
      }
    ]
  })
}
```

## Remediation steps
1. Never write a `Deny` statement with `Principal: "*"` and a broad S3 write action unless it includes a `Condition` that excludes your administrative/break-glass principals.
2. Use `NotAction` instead of `Action` where the intent is "deny everything except these specific actions" — this changes how the check (and, more importantly, AWS policy evaluation) treats the statement.
3. Test bucket policy changes with the IAM Policy Simulator or `aws s3api get-bucket-policy` + manual review before applying to production buckets.
4. If already locked out, note that AWS root-cause recovery for this scenario typically requires contacting AWS Support — plan and review policies carefully beforehand to avoid this state.
5. Consider using S3 Block Public Access and bucket-level IAM condition keys (e.g., `aws:PrincipalOrgID`) as an alternative, less risky way to restrict access instead of broad denies.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3ProtectAgainstPolicyLockout.py
- AWS docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html
