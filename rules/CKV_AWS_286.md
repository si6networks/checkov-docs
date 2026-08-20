# CKV_AWS_286: Ensure IAM policies does not allow privilege escalation
## Severity
**MEDIUM** (score: 5.0/10)

An IAM policy permitting privilege escalation actions lets a principal with limited initial permissions grant themselves broader access, up to full administrative control, making this a direct path to complete account compromise.

## Summary
This check fails when an IAM policy document (attached inline or standalone) contains a combination of IAM permissions that is a known privilege-escalation vector — actions that would let a principal grant themselves broader permissions than they were explicitly given.

## Applicability
- **Framework:** Terraform
- **Resources:** `aws_iam_group_policy`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_ssoadmin_permission_set_inline_policy`

## Why it matters
IAM privilege escalation occurs when a principal, using only permissions it already has, can obtain additional permissions it was not directly granted — for example, a user with `iam:CreatePolicyVersion` or `iam:AttachUserPolicy` on themselves can grant themselves `AdministratorAccess` without ever needing that permission explicitly. There are dozens of documented escalation paths (via `iam:PassRole` + `lambda:CreateFunction`, `iam:CreateAccessKey` for another user, `ec2:RunInstances` with an attached instance profile, `glue:UpdateDevEndpoint`, etc.). This check leverages the open-source `cloudsplaining` policy-analysis engine, which encodes a comprehensive, curated list of these known escalation techniques. A policy that appears narrowly scoped on paper can still be a full path to account takeover if it includes even one of these actions without a compensating condition — making this one of the highest-impact IAM misconfigurations to catch before deployment.

## How Checkov evaluates this
This check is implemented via `BaseTerraformCloudsplainingResourceIAMCheck`, which extracts the policy document attached to the resource and hands it to the `cloudsplaining` library's `PolicyDocument.allows_privilege_escalation` property. That property runs the policy's statements against cloudsplaining's built-in database of privilege-escalation action-combinations (e.g., `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:PassRole`+service combos, `sts:AssumeRole` chains, etc.) and returns any matches found. If `allows_privilege_escalation` returns one or more escalation findings, results are flattened into a list of the specific IAM actions/techniques involved, and the check **fails** with those actions listed as evidence; an empty result **passes**.

## Non-compliant example
```hcl
resource "aws_iam_policy" "bad" {
  name = "escalation-risk"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]
        Resource = "*"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_policy" "good" {
  name = "scoped-policy-management"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]
        Resource = "arn:aws:iam::123456789012:policy/app-specific-policy-*"
        Condition = {
          Bool = { "aws:MultiFactorAuthPresent" = "true" }
        }
      }
    ]
  })
}
```

## Remediation steps
1. Run `cloudsplaining` (or Checkov's report) to see exactly which action(s) triggered the finding for the policy in question.
2. Scope the `Resource` element to specific ARNs instead of `"*"` so the risky action can only be used against resources it's meant for, not arbitrary IAM entities.
3. Where possible, remove the escalation-enabling action entirely if it isn't actually needed (many are broad admin conveniences that aren't required day-to-day).
4. Add restrictive `Condition` blocks (e.g., MFA required, source IP restrictions, `iam:PermissionsBoundary` requirements) if the action must remain.
5. Attach a permissions boundary to any principal holding this policy so even if escalation is attempted, the resulting effective permissions are capped.
6. Re-test with Checkov/cloudsplaining after remediation to confirm the specific escalation path is closed — some techniques require removing more than one action from the same policy.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMPrivilegeEscalation.py
- cloudsplaining docs: https://cloudsplaining.readthedocs.io/en/latest/glossary/privilege-escalation.html
