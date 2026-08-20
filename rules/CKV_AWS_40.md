# CKV_AWS_40: Ensure IAM policies are attached only to groups or roles
## Severity
**LOW** (score: 2.0/10)

Attaching IAM policies directly to users instead of groups/roles increases the chance that a principal accumulates or retains excessive privileges over time, an indirect access-management risk rather than an immediate exploit path.

## Summary
This check ensures IAM policies are never attached directly to individual IAM users; instead they should be attached to IAM groups or roles, reducing the complexity (and error-proneness) of access management.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Frameworks:** CloudFormation, Terraform
- **Resource/entity types:**
  - CloudFormation: `AWS::IAM::Policy` (inspects the `Properties/Users` list)
  - Terraform: `aws_iam_policy_attachment` (inspects `users`), `aws_iam_user_policy` and `aws_iam_user_policy_attachment` (inspects `user`)

## Why it matters
Attaching policies directly to individual users creates permission sprawl that is hard to audit and easy to get wrong: over time, engineers accumulate ad-hoc, user-specific grants that nobody remembers the justification for, permissions aren't revoked consistently when someone changes teams or leaves, and there's no single source of truth for "what can this class of user do." Using groups (or roles, for programmatic/service access) centralizes permission management: you can review a group's policy set once and know it applies uniformly to all its members, onboard/offboard by group membership change alone, and more easily spot drift or excessive privilege during audits. Direct user-attached policies are a common root cause of privilege creep and orphaned/forgotten grants that later show up in a security review or an incident.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` (fails when a "forbidden" value/key is present):
- **CloudFormation:** inspects `Properties/Users` on `AWS::IAM::Policy` — if this list is present with any value (`ANY_VALUE` forbidden), the check **FAILS**.
- **Terraform:**
  - For `aws_iam_policy_attachment`, inspects the `users` argument — if present (non-empty), **FAILS**.
  - For `aws_iam_user_policy` and `aws_iam_user_policy_attachment`, inspects the `user` argument — since these resource types exist specifically to attach a policy to a user, their mere presence with a `user` value **FAILS** the check (these resource types are inherently non-compliant unless removed/replaced with group/role-based equivalents).
- Absence of the `Users`/`users`/`user` key → **PASS**.

## Non-compliant example
```hcl
resource "aws_iam_user_policy_attachment" "example" {
  user       = aws_iam_user.dev.name
  policy_arn = aws_iam_policy.s3_read.arn
}
```

## Remediated example
```hcl
resource "aws_iam_group" "developers" {
  name = "developers"
}

resource "aws_iam_group_policy_attachment" "example" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.s3_read.arn
}

resource "aws_iam_group_membership" "dev_team" {
  name  = "dev-team-membership"
  group = aws_iam_group.developers.name
  users = [aws_iam_user.dev.name]
}
```

## Remediation steps
1. Replace `aws_iam_user_policy_attachment` / `aws_iam_user_policy` resources with an `aws_iam_group` and `aws_iam_group_policy_attachment` (or `aws_iam_group_policy` for inline policies).
2. Add the affected users to the group via `aws_iam_group_membership` (or `aws_iam_user_group_membership`).
3. For CloudFormation, remove the `Users` property from `AWS::IAM::Policy` and instead reference `Groups` or `Roles`.
3. For workload/service access (not human users), use IAM roles with trust policies (e.g., assumed via EC2 instance profiles, Lambda execution roles, or OIDC federation) rather than user-attached policies at all.
4. Audit existing accounts for any remaining direct user-policy attachments and migrate them to groups as part of a cleanup pass — this is usually non-disruptive since it doesn't change the underlying permissions, just how they are organized.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMPolicyAttachedToGroupOrRoles.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/IAMPolicyAttachedToGroupOrRoles.py)
- [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
