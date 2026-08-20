# CKV_AWS_109: Ensure IAM policies does not allow permissions management / resource exposure without constraints

## Severity
**LOW** (score: 2.0/10)

IAM policies that permit permissions-management or resource-exposure actions without ARN/Condition constraints act as a stepping stone to privilege escalation or public resource exposure, though they require an additional action to be fully weaponized.

## Summary
Fails when an IAM policy grants permissions-management actions (actions that can modify IAM permissions or resource-based policies, e.g. `iam:PutRolePolicy`, `iam:AttachUserPolicy`, `sns:AddPermission`) over resources without any restricting `Condition` or resource ARN constraint.

## Applicability
- **Terraform**: `aws_iam_policy_document` (data source)
- **CloudFormation**: `AWS::IAM::Group`, `AWS::IAM::ManagedPolicy`, `AWS::IAM::Policy`, `AWS::IAM::Role`, `AWS::IAM::User`

Both implementations delegate the actual analysis to the third-party `cloudsplaining` library, which parses the IAM policy document/statements attached to the resource.

## Why it matters
Permissions-management actions let a principal change IAM policies, attach/detach policies, or modify resource-based access policies (e.g. an S3 bucket policy, an SNS topic policy, a KMS key policy). If a role or user can invoke these actions on `Resource: "*"` (or on a broad, unconstrained resource set) with no `Condition` clause, a compromised or over-privileged identity can:
- Grant itself or any other principal additional permissions (a path to privilege escalation).
- Attach a policy to a resource that exposes it publicly (e.g. add a bucket policy allowing `s3:GetObject` to `"*"`), causing unintended data exposure.
- Escape whatever narrow permissions were originally intended, since permissions-management actions are effectively "meta" permissions that control all other permissions.

Constraining these actions with an ARN scope or an IAM `Condition` (e.g. `aws:ResourceTag`, `iam:PermissionsBoundary`) limits the blast radius so a single misused policy cannot cascade into full account compromise.

## How Checkov evaluates this
Checkov does not implement the IAM logic itself — it hands the parsed policy document to `cloudsplaining`'s `PolicyDocument` object and reads the `permissions_management_without_constraints` property. Cloudsplaining maintains a curated list of IAM actions classified as "Permissions management" (from its actions dataset) and a separate list of actions known to support resource-level or condition-based constraints. For each statement in the policy:
- If the statement's actions include a "permissions management" action,
- AND the statement does not scope the `Resource` to specific ARNs and does not include a `Condition` block that meaningfully restricts it (i.e., it applies to `"*"` or is otherwise unconstrained),

then that finding is added to `permissions_management_without_constraints`. Checkov's check simply returns `CheckResult.FAILED` if this list is non-empty, otherwise `PASSED`.

## Non-compliant example
```hcl
data "aws_iam_policy_document" "bad" {
  statement {
    sid       = "UnconstrainedPermissionsManagement"
    effect    = "Allow"
    actions   = ["iam:PutRolePolicy", "iam:AttachRolePolicy"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "bad" {
  name   = "unconstrained-permissions-mgmt"
  policy = data.aws_iam_policy_document.bad.json
}
```

## Remediated example
```hcl
data "aws_iam_policy_document" "good" {
  statement {
    sid       = "ConstrainedPermissionsManagement"
    effect    = "Allow"
    actions   = ["iam:PutRolePolicy", "iam:AttachRolePolicy"]
    resources = ["arn:aws:iam::123456789012:role/app-limited-role"]

    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = ["arn:aws:iam::123456789012:policy/app-boundary"]
    }
  }
}

resource "aws_iam_policy" "good" {
  name   = "constrained-permissions-mgmt"
  policy = data.aws_iam_policy_document.good.json
}
```

## Remediation steps
1. Identify which statements grant permissions-management actions (IAM, org, resource-policy-modifying actions like `iam:*Policy*`, `organizations:*`, `s3:PutBucketPolicy`, `sns:AddPermission`, `sqs:AddPermission`, `kms:PutKeyPolicy`, etc.).
2. Replace `Resource: "*"` with explicit ARNs scoped to the specific roles/policies/resources the principal legitimately needs to manage.
3. Add a `Condition` block (e.g. `iam:PermissionsBoundary`, `aws:ResourceTag/...`) to further constrain when the action is allowed, especially for actions that can't be scoped by ARN alone.
4. Where possible, require a permissions boundary on any role/user this policy can modify, so even a successful escalation is capped.
5. Re-run `checkov` (or `cloudsplaining`) locally to confirm the statement no longer appears in `permissions_management_without_constraints`.
6. Note this check applies to the rendered IAM policy document, so also review policies attached via `aws_iam_role_policy`, `aws_iam_user_policy`, and inline CloudFormation `PolicyDocument` blocks, not just standalone `aws_iam_policy` resources.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/IAMPermissionsManagement.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/IAMPermissionsManagement.py
