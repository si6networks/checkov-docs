# CKV_AWS_1: Ensure IAM policies that allow full "*-*" administrative privileges are not created
## Severity
**LOW** (score: 2.0/10)

The check flags IAM policy statements that grant Allow on Action '*' and Resource '*', i.e. full unrestricted administrative privileges, which if attached anywhere gives complete control over the AWS account.

## Summary
This check ensures that IAM policy documents (defined via Terraform's `aws_iam_policy_document` data source or in a Serverless Framework `provider.iam` block) do not grant `Allow` on `Action: "*"` combined with `Resource: "*"`, which would be a fully unrestricted administrative policy.

## Applicability
- **Terraform**: the `aws_iam_policy_document` data source (any statement block).
- **Serverless Framework**: the `serverless_aws` provider's IAM role statements (`provider.iamRoleStatements`).

## Why it matters
A policy statement with `Effect: Allow`, `Action: "*"`, and `Resource: "*"` grants the attached principal (IAM user, role, or Lambda execution role) unrestricted access to every action on every resource in the AWS account — equivalent to full administrator access, with no boundary. If this policy is attached to a service, application, or a role that is more broadly assumable than intended, any compromise of that identity (leaked credentials, SSRF against an EC2 instance profile, a vulnerable Lambda function) gives the attacker complete control of the AWS account: they can create new users, exfiltrate data from any S3 bucket, modify security groups, disable logging/CloudTrail, or spin up resources for cryptomining — with no way to contain the blast radius. This directly violates the principle of least privilege, which is the primary control against lateral movement and privilege escalation once any single credential is compromised.

## How Checkov evaluates this
Two related implementations, both checking for the *combination* of wildcard action + wildcard resource + allow effect:
- **Terraform** (`aws_iam_policy_document` data check): iterates each `statement` block; if `effect` is `"Allow"` (or omitted, since Allow is the default) and `actions` contains `"*"` and `resources` contains `"*"`, the check **FAILS**. Any statement not matching this exact combination **PASSES**.
- **Serverless** (`serverless_aws` function check): iterates the IAM role statements token; if a statement has `Action` containing `"*"`, `Effect == "Allow"`, and `Resource` containing `"*"`, the check **FAILS**. Otherwise **PASSES**.

## Non-compliant example
```hcl
data "aws_iam_policy_document" "admin" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "admin" {
  name   = "admin-policy"
  policy = data.aws_iam_policy_document.admin.json
}
```

## Remediated example
```hcl
data "aws_iam_policy_document" "s3_read_only" {
  statement {
    effect  = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::my-app-bucket",
      "arn:aws:s3:::my-app-bucket/*",
    ]
  }
}

resource "aws_iam_policy" "s3_read_only" {
  name   = "s3-read-only-policy"
  policy = data.aws_iam_policy_document.s3_read_only.json
}
```

## Remediation steps
1. Enumerate the exact set of AWS API actions the identity actually needs (use CloudTrail/Access Analyzer or IAM Access Analyzer policy generation to derive a minimal set) instead of `"*"`.
2. Scope `resources` to specific ARNs (bucket, table, function, etc.) rather than `"*"`; use ARN patterns/wildcards only within a single resource type/prefix, not across all resources.
3. Split broad policies into multiple narrowly-scoped statements/policies attached only to the roles/functions that need them.
4. For Serverless Framework, apply the same principle to `provider.iamRoleStatements` — write function-specific statements rather than a single account-wide admin statement.
5. If genuine break-glass admin access is required, use a separate, tightly access-controlled role with strong authentication (MFA, short session duration) rather than embedding it in application infrastructure code.
6. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/AdminPolicyDocument.py)
- [Checkov check source (Serverless)](https://github.com/bridgecrewio/checkov/blob/main/checkov/serverless/checks/function/aws/AdminPolicyDocument.py)
- [AWS IAM: Security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
