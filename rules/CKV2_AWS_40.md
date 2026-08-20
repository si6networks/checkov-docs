# CKV2_AWS_40: Ensure AWS IAM policy does not allow full IAM privileges
## Severity
**MEDIUM** (score: 5.0/10)

This check flags IAM policies that grant wildcard `iam:*` or `*` administrative actions, which effectively gives a principal the ability to escalate privileges and take over the entire AWS account.

## Summary
This check fails when an IAM policy (managed, inline, or an SSO permission set inline policy) contains an `Allow` statement granting the wildcard action `iam:*` or the fully unrestricted `*` action, which effectively grants unrestricted control over the account's identity and access management.

## Applicability
- **IaC framework:** Terraform
- **Resource/entity types:** `aws_iam_group_policy`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_ssoadmin_permission_set_inline_policy`, `data.aws_iam_policy_document`

## Why it matters
IAM is the control plane for every other AWS security boundary. An identity holding `iam:*` (or `*`) can create new users/roles, attach `AdministratorAccess`, rotate or delete other principals' credentials, modify trust policies, or grant itself any additional permission across the account — regardless of what other guardrails (SCPs aside) are in place. A policy this broad turns a single compromised credential, a misconfigured CI pipeline, or an over-permissioned Lambda execution role into a full account takeover. This class of over-privilege is the textbook root cause behind lateral-movement and privilege-escalation incidents in AWS environments: an attacker who compromises even a low-value workload with an `iam:*` policy can pivot straight to full administrative control.

## How Checkov evaluates this
This is a graph-based JSON policy (not Python). It inspects the `Allow`-effect `Action` array of the policy document, using a JSONPath filter (`Statement[?(@.Effect == Allow)].Action[*]`):
- **FAIL** if any `Allow` statement's `Action` list contains the literal string `iam:*` OR the literal string `*`.
- **PASS** if neither wildcard value is present, i.e. `Action` is not-equal to `iam:*` AND not-equal to `*` (checked via `jsonpath_not_equals` combined with `and`).
- The same logic is applied across four different attribute paths depending on resource type: `policy.Statement[*]` for `aws_iam_policy`/`aws_iam_role_policy`/`aws_iam_group_policy`/`aws_iam_user_policy`, `inline_policy.Statement[*]` for `aws_ssoadmin_permission_set_inline_policy`, and `statement[*].actions[*]` (lowercase field names) for `data.aws_iam_policy_document`.
- Narrower wildcards like `iam:Create*` or `iam:Put*` are NOT flagged by this specific check — only the full `iam:*` or the universal `*` action trips it.

## Non-compliant example
```hcl
resource "aws_iam_policy" "bad" {
  name = "full-iam-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iam:*"
        Resource = "*"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_policy" "good" {
  name = "scoped-iam-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:ListUsers",
          "iam:GetRole",
          "iam:ListRoles"
        ]
        Resource = "*"
      }
    ]
  })
}
```

## Remediation steps
1. Identify the specific IAM actions the workload actually needs (e.g. `iam:PassRole`, `iam:GetRole`) instead of granting the entire `iam:*` namespace.
2. Replace the wildcard `Action` value with an explicit list of the minimum required actions.
3. Scope the `Resource` element to specific ARNs (roles/users/policies) rather than `*` wherever the API supports resource-level permissions.
4. If broad IAM administration is genuinely required for a break-glass or platform-admin role, isolate that policy to a tightly access-controlled principal, require MFA, and consider a permissions boundary or SCP as compensating controls rather than exempting the check.
5. Re-run `checkov` after the change to confirm the `Allow`/`iam:*` combination no longer appears in the rendered policy document, including any `data.aws_iam_policy_document` sources referenced by `jsonencode`/`source_policy_documents`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/IAMPolicyNotAllowFullIAMAccess.json
