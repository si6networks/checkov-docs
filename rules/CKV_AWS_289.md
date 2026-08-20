# CKV_AWS_289: Ensure IAM policies does not allow permissions management / resource exposure without constraints
## Severity
**HIGH** (score: 7.5/10)

IAM policies allowing unconstrained permissions-management or resource-exposure actions let a principal alter access policies or make resources public, enabling broad privilege or exposure escalation across the account.

## Summary
This check fails when an IAM policy document grants "permissions management" actions (the ability to modify IAM/resource policies or otherwise change access controls) over an unconstrained `Resource` scope, per cloudsplaining's analysis.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resources:** `aws_iam_group_policy`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_ssoadmin_permission_set_inline_policy`

## Why it matters
"Permissions management without constraints" covers actions like `iam:PutRolePolicy`, `iam:AttachRolePolicy`, `s3:PutBucketPolicy`, `sqs:SetQueueAttributes`, `kms:PutKeyPolicy`, and similar — actions that let a principal alter who can access a resource, effectively controlling the security perimeter of that resource rather than just using it. When such actions are granted with `Resource: "*"` (no scoping), a principal (or an attacker who compromises it) can rewrite access policies on resources across the entire account — attaching an admin policy to a role, opening an S3 bucket to the public, or granting a KMS key to an external account — without needing any of the target permissions directly. This is a distinct and often more dangerous risk than plain privilege escalation because it can expose *other* resources (not just the caller's own permissions) to unauthorized parties, e.g., silently making a bucket public or a queue readable by any AWS account.

## How Checkov evaluates this
The check is implemented via `BaseTerraformCloudsplainingResourceIAMCheck`, delegating to cloudsplaining's `PolicyDocument.permissions_management_without_constraints` property. Cloudsplaining flags actions from its permissions-management category (policy/resource-policy modification actions) when they are granted without resource-level restriction (i.e., effectively `Resource: "*"` or otherwise unconstrained). If any such actions are found, the check **fails** with the offending actions listed; an empty result **passes**.

## Non-compliant example
```hcl
resource "aws_iam_policy" "bad" {
  name = "permissions-mgmt-risk"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:AttachRolePolicy", "iam:PutRolePolicy", "s3:PutBucketPolicy"]
        Resource = "*"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_policy" "good" {
  name = "scoped-permissions-mgmt"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutBucketPolicy"]
        Resource = "arn:aws:s3:::app-specific-bucket"
      }
    ]
  })
}
```

## Remediation steps
1. Scope the `Resource` element of every permissions-management action to the specific resource(s) the workload is meant to manage, not `"*"`.
2. Remove IAM-modifying actions (`iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:AttachUserPolicy`, etc.) from application/service roles entirely unless the role's job is genuinely to manage IAM.
3. Where a role must manage resource policies, add conditions (e.g., `aws:ResourceAccount`, tag-based conditions, `iam:PermissionsBoundary` enforcement) to prevent it from being used to open access to unintended resources.
4. Centralize any legitimately broad permissions-management capability into a small, tightly monitored administrative role rather than distributing it across many policies.
5. Re-run Checkov/cloudsplaining after scoping to confirm the finding clears, and review CloudTrail for any historical use of the over-broad permission that may indicate prior misuse.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMPermissionsManagement.py
- cloudsplaining docs: https://cloudsplaining.readthedocs.io/en/latest/glossary/permissions-management.html
