# CKV_AWS_290: Ensure IAM policies does not allow write access without constraints
## Severity
**HIGH** (score: 7.5/10)

IAM policies granting unconstrained write access let a principal create, modify, or delete resources broadly, which can degrade integrity and availability though it is less severe than escalation or credential-exposure paths.

## Summary
This check fails when an IAM policy document grants write-level actions (create/update/delete data or resources) over an unconstrained `Resource` scope, per cloudsplaining's analysis, meaning the principal can modify or destroy data/resources broadly rather than within a defined boundary.

## Applicability
- **Framework:** Terraform
- **Resources:** `aws_iam_group_policy`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_ssoadmin_permission_set_inline_policy`

## Why it matters
Write actions granted with `Resource: "*"` (e.g., `s3:PutObject`, `s3:DeleteObject`, `dynamodb:DeleteTable`, `ec2:TerminateInstances`) let a principal modify or destroy data and infrastructure across the entire account rather than being confined to what the workload actually needs to touch. This dramatically increases the blast radius of both accidental mistakes (a buggy deployment script that wipes the wrong S3 bucket) and malicious activity (a compromised credential used to delete backups, overwrite audit logs, or terminate production instances to cover tracks or cause outages). Unconstrained write access is a frequent root cause of destructive incidents — ransomware-style data destruction, insider sabotage, or simple automation bugs — precisely because nothing in the policy stops the action from reaching resources outside its intended scope.

## How Checkov evaluates this
The check is implemented via `BaseTerraformCloudsplainingResourceIAMCheck`, delegating to cloudsplaining's `PolicyDocument.write_actions_without_constraints` property, which flags write-capable actions in the policy that are not scoped to specific resource ARNs (effectively `Resource: "*"` or similarly unconstrained). If any such actions are found, the check **fails**, listing the offending actions; an empty result **passes**.

## Non-compliant example
```hcl
resource "aws_iam_policy" "bad" {
  name = "write-without-constraints"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:DeleteObject", "dynamodb:DeleteItem"]
        Resource = "*"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_policy" "good" {
  name = "scoped-write-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:DeleteObject"]
        Resource = "arn:aws:s3:::app-uploads-bucket/*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:DeleteItem"]
        Resource = "arn:aws:dynamodb:us-east-1:123456789012:table/app-orders"
      }
    ]
  })
}
```

## Remediation steps
1. Identify the specific write actions flagged and replace `Resource: "*"` with the exact ARNs (bucket, table, queue, instance, etc.) the workload legitimately needs to write to.
2. Split overly broad policies into resource-scoped statements aligned with each distinct workload/service the role serves.
3. For destructive actions in particular (`Delete*`, `Terminate*`, `Remove*`), consider adding explicit `Deny` statements or SCPs at the organization level as a backstop even after scoping the `Allow`.
4. Enable versioning/MFA-delete on S3 buckets and point-in-time recovery on DynamoDB tables as compensating controls against accidental or malicious writes even after IAM scoping.
5. Re-scan with Checkov/cloudsplaining after remediation to confirm the unconstrained-write finding clears.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMWriteAccess.py
- cloudsplaining docs: https://cloudsplaining.readthedocs.io/en/latest/glossary/write-actions.html
