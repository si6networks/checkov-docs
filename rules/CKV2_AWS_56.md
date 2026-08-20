# CKV2_AWS_56: Ensure AWS Managed IAMFullAccess IAM policy is not used
## Severity
**HIGH** (score: 7.5/10)

Attaching the AWS-managed IAMFullAccess policy grants unrestricted IAM administrative control, allowing privilege escalation to full account takeover.

## Summary
This check fails when any IAM principal — a role, user, or group — has the AWS-managed `IAMFullAccess` policy attached, whether by direct managed-policy-attachment resources, via a role's `managed_policy_arns`, via SSO permission set attachment, or referenced through a `data.aws_iam_policy` data source by name or ARN.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_iam_group_policy_attachment`, `aws_iam_policy_attachment`, `aws_iam_role`, `aws_iam_role_policy_attachment`, `aws_iam_user_policy_attachment`, `aws_ssoadmin_managed_policy_attachment`, `data.aws_iam_policy`

## Why it matters
`IAMFullAccess` is one of the most dangerous AWS-managed policies that can be attached to a principal, because it grants unrestricted create/modify/delete access over all IAM users, groups, roles, and policies in the account. A principal with this policy can create a new IAM user with `AdministratorAccess`, attach `AdministratorAccess` to itself or any other principal, modify any role's trust policy to allow assumption from an external/attacker-controlled account, or delete other users' access keys and MFA devices to lock out legitimate admins. Effectively, `IAMFullAccess` is equivalent to full account administrative access once you account for privilege-escalation paths through IAM itself — it's a superset of the risk covered by CKV2_AWS_40 (custom policies granting `iam:*`), applied specifically to this one commonly-reached-for AWS managed policy, which teams sometimes attach as a "quick fix" during development and never remove.

## How Checkov evaluates this
This is a graph-based JSON policy wrapped in a `not(or(...))` — meaning it **PASSES** only if none of the following are true, and **FAILS** if any one of them is:
1. `data.aws_iam_policy.name` equals `"IAMFullAccess"`.
2. `data.aws_iam_policy.arn` contains `"IAMFullAccess"`.
3. `policy_arn` on `aws_iam_policy_attachment`, `aws_iam_user_policy_attachment`, `aws_iam_role_policy_attachment`, or `aws_iam_group_policy_attachment` contains `"IAMFullAccess"`.
4. `aws_iam_role.managed_policy_arns.*` contains `"IAMFullAccess"`.
5. `aws_ssoadmin_managed_policy_attachment.managed_policy_arn` contains `"IAMFullAccess"`.
- In short: any reference to the `IAMFullAccess` managed policy — by name, ARN substring, direct attachment, inline `managed_policy_arns` list on a role, or SSO permission-set attachment — triggers a FAIL, regardless of which resource type or attachment mechanism is used.

## Non-compliant example
```hcl
resource "aws_iam_role" "bad" {
  name = "ci-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/IAMFullAccess"]
}
```

## Remediated example
```hcl
resource "aws_iam_policy" "scoped_iam" {
  name = "scoped-iam-role-management"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy"
        ]
        Resource = "arn:aws:iam::123456789012:role/ci-managed/*"
      }
    ]
  })
}

resource "aws_iam_role" "good" {
  name = "ci-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "good" {
  role       = aws_iam_role.good.name
  policy_arn = aws_iam_policy.scoped_iam.arn
}
```

## Remediation steps
1. Locate every attachment of `arn:aws:iam::aws:policy/IAMFullAccess` — check `managed_policy_arns` on roles, `aws_iam_*_policy_attachment` resources, `aws_iam_policy_attachment`, and SSO permission set attachments.
2. Determine the actual IAM actions the principal needs (e.g. creating roles under a specific path, attaching a limited set of policies) and author a scoped customer-managed policy instead, ideally with a `Resource` constrained to a specific path/prefix (e.g. `role/ci-managed/*`) and a `Condition` restricting which policies can be attached (`iam:PolicyARN` condition key).
3. Replace the `IAMFullAccess` attachment with the new scoped policy's attachment.
4. If a break-glass/emergency-admin use case is the actual justification, isolate that principal behind strong controls (MFA-required assumption, short session duration, dedicated break-glass account) rather than attaching this policy to routine service/CI roles.
5. After removing the policy, test the affected workflow (CI pipeline, application) to confirm the newly scoped policy still covers all legitimately-required IAM operations.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/IAMManagedIAMFullAccessPolicy.json
- AWS docs: https://docs.aws.amazon.com/aws-managed-policy/latest/reference/IAMFullAccess.html
